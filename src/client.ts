import type {
  SessionClientConfig,
  SessionEvent,
  SessionEventHandler,
  SessionState,
  SessionStatus,
  GetSessionOptions,
  LogoutOptions,
  SwitchAccountOptions,
} from "./types";
import { SessionError } from "./types";

type SessionSyncMessageV1 = {
  v: 1;
  type: "SESSION_CHANGED";
  at: number;
  sourceId: string;
  fingerprint: string;
};

function canUseBroadcastChannel(): boolean {
  return typeof BroadcastChannel !== "undefined";
}

function createTabId(): string {
  // Avoid relying on crypto in older runtimes.
  const rnd = Math.random().toString(16).slice(2);
  return `tab_${Date.now().toString(16)}_${rnd}`;
}

const DEFAULT_CONFIG: Required<
  Pick<
    SessionClientConfig,
    | "baseUrl"
    | "sessionEndpoint"
    | "logoutEndpoint"
    | "switchAccountEndpoint"
    | "debug"
  >
> = {
  baseUrl: "",
  sessionEndpoint: "/api/auth/session",
  logoutEndpoint: "/api/auth/logout",
  switchAccountEndpoint: "/api/auth/switch-account",
  debug: false,
};

const DEFAULT_STATE: SessionState = {
  status: "loading",
  user: null,
  session: null,
  error: null,
  checkedAt: null,
};

type SessionApiResponse = {
  status?: SessionStatus;
  user?: SessionState["user"];
  session?: SessionState["session"];
};

export class DouverySessionClient {
  private config: SessionClientConfig;
  private state: SessionState = { ...DEFAULT_STATE };
  private events = new Set<SessionEventHandler>();
  private cache: { value: SessionState; at: number } | null = null;

  private syncSourceId = createTabId();
  private syncChannel: BroadcastChannel | null = null;
  private suppressNextSyncBroadcast = 0;
  private lastSyncFingerprint: string | null = null;

  constructor(config: SessionClientConfig = {}) {
    this.config = {
      ...DEFAULT_CONFIG,
      ...config,
    };

    this.initSyncChannel();
  }

  /**
   * Cleanup browser resources (BroadcastChannel listeners).
   * Safe to call multiple times.
   */
  dispose(): void {
    try {
      this.syncChannel?.close();
    } finally {
      this.syncChannel = null;
    }
  }

  onSessionExpired(handler: SessionEventHandler): () => void {
    this.events.add(handler);
    return () => this.events.delete(handler);
  }

  subscribe(handler: SessionEventHandler): () => void {
    this.events.add(handler);
    return () => this.events.delete(handler);
  }

  getState(): SessionState {
    return { ...this.state };
  }

  async getSession(options: GetSessionOptions = {}): Promise<SessionState> {
    if (
      !options.bypassCache &&
      this.cache &&
      Date.now() - this.cache.at < 3000
    ) {
      return this.cache.value;
    }

    try {
      const response = await this.request(this.config.sessionEndpoint!, {
        method: "GET",
        signal: options.signal,
      });

      if (response.status === 401) {
        return this.setState({
          status: "unauthenticated",
          user: null,
          session: null,
          error: null,
          checkedAt: Date.now(),
        });
      }

      if (
        response.status === 403 ||
        response.status === 419 ||
        response.status === 440
      ) {
        const expiredState = this.setState({
          status: "expired",
          user: null,
          session: null,
          error: new SessionError(
            "session_expired",
            "Session expired",
            undefined,
            response.status,
          ),
          checkedAt: Date.now(),
        });
        this.emit({ type: "SESSION_EXPIRED", state: expiredState });
        return expiredState;
      }

      if (!response.ok) {
        throw new SessionError(
          "unknown_error",
          "Failed to resolve session",
          undefined,
          response.status,
        );
      }

      const data = (await response.json()) as SessionApiResponse;
      const status = this.normalizeStatus(data.status, data.user ?? null);
      const next = this.setState({
        status,
        user: data.user ?? null,
        session: data.session ?? null,
        error: null,
        checkedAt: Date.now(),
      });

      if (next.status === "expired") {
        this.emit({ type: "SESSION_EXPIRED", state: next });
      } else {
        this.emit({ type: "SESSION_UPDATED", state: next });
      }

      this.maybeBroadcastSessionChange(next);

      return next;
    } catch (error) {
      const sessionError =
        error instanceof SessionError
          ? error
          : new SessionError("network_error", "Failed to fetch session", error);

      const next = this.setState({
        ...this.state,
        error: sessionError,
        checkedAt: Date.now(),
      });
      this.emit({ type: "SESSION_ERROR", error: sessionError });
      return next;
    }
  }

  async logout(options: LogoutOptions = {}): Promise<void> {
    const response = await this.request(this.config.logoutEndpoint!, {
      method: "POST",
      signal: options.signal,
    });

    if (!response.ok && response.status !== 401) {
      throw new SessionError(
        "unknown_error",
        "Logout failed",
        undefined,
        response.status,
      );
    }

    const next = this.setState({
      status: "unauthenticated",
      user: null,
      session: null,
      error: null,
      checkedAt: Date.now(),
    });

    this.emit({ type: "SESSION_UPDATED", state: next });
    this.maybeBroadcastSessionChange(next);
  }

  async switchAccount(
    accountId: string,
    options: SwitchAccountOptions = {},
  ): Promise<SessionState> {
    if (!accountId || !accountId.trim()) {
      throw new SessionError("invalid_response", "accountId is required");
    }

    const response = await this.request(this.config.switchAccountEndpoint!, {
      method: "POST",
      signal: options.signal,
      body: JSON.stringify({ accountId }),
      headers: {
        "Content-Type": "application/json",
      },
    });

    if (response.status === 401) {
      return this.setState({
        status: "unauthenticated",
        user: null,
        session: null,
        error: null,
        checkedAt: Date.now(),
      });
    }

    if (!response.ok) {
      throw new SessionError(
        "unknown_error",
        "Switch account failed",
        undefined,
        response.status,
      );
    }

    const next = await this.getSession({
      signal: options.signal,
      bypassCache: true,
    });

    // Ensure the account change propagates even if state remains "authenticated".
    this.maybeBroadcastSessionChange(next, { force: true });
    return next;
  }

  private normalizeStatus(
    status: SessionStatus | undefined,
    user: SessionState["user"],
  ): SessionStatus {
    if (
      status === "authenticated" ||
      status === "unauthenticated" ||
      status === "expired"
    ) {
      return status;
    }
    return user ? "authenticated" : "unauthenticated";
  }

  private setState(next: SessionState): SessionState {
    this.state = next;
    this.cache = { value: next, at: Date.now() };
    return next;
  }

  private initSyncChannel(): void {
    if (!canUseBroadcastChannel()) return;
    if (this.config.broadcastChannel === false) return;

    const name =
      typeof this.config.broadcastChannel === "string" &&
      this.config.broadcastChannel.trim()
        ? this.config.broadcastChannel.trim()
        : "douvery:auth:session";

    try {
      const channel = new BroadcastChannel(name);
      channel.onmessage = (event: MessageEvent) => {
        const msg = event?.data as Partial<SessionSyncMessageV1> | undefined;
        if (!msg || msg.v !== 1 || msg.type !== "SESSION_CHANGED") return;
        if (!msg.sourceId || msg.sourceId === this.syncSourceId) return;

        // Avoid broadcast storms: refresh local state but don't re-broadcast.
        this.suppressNextSyncBroadcast++;
        void this.getSession({ bypassCache: true }).finally(() => {
          this.suppressNextSyncBroadcast = Math.max(
            0,
            this.suppressNextSyncBroadcast - 1,
          );
        });
      };

      this.syncChannel = channel;
    } catch (error) {
      // If BroadcastChannel fails (permissions/unsupported), ignore.
      this.log("Failed to init BroadcastChannel", error);
      this.syncChannel = null;
    }
  }

  private getSyncFingerprint(state: SessionState): string {
    const userId = state.user?.id ?? "";
    const sessionId = (state.session as any)?.sessionId ?? "";
    return `${state.status}:${userId}:${sessionId}`;
  }

  private maybeBroadcastSessionChange(
    state: SessionState,
    options?: { force?: boolean },
  ): void {
    if (!this.syncChannel) return;
    if (this.suppressNextSyncBroadcast > 0) return;

    const fingerprint = this.getSyncFingerprint(state);
    if (!options?.force && this.lastSyncFingerprint === fingerprint) return;
    this.lastSyncFingerprint = fingerprint;

    const msg: SessionSyncMessageV1 = {
      v: 1,
      type: "SESSION_CHANGED",
      at: Date.now(),
      sourceId: this.syncSourceId,
      fingerprint,
    };

    try {
      this.syncChannel.postMessage(msg);
    } catch (error) {
      this.log("Failed to post sync message", error);
    }
  }

  private emit(event: SessionEvent): void {
    for (const handler of this.events) {
      try {
        handler(event);
      } catch (error) {
        this.log("Event handler error", error);
      }
    }
  }

  private async request(path: string, init: RequestInit): Promise<Response> {
    const fetcher = this.config.fetchImpl ?? fetch;
    const base = this.config.baseUrl ?? "";
    const url = `${base}${path}`;

    return fetcher(url, {
      credentials: "include",
      ...init,
      headers: {
        ...(this.config.defaultHeaders ?? {}),
        ...(init.headers ?? {}),
      },
    });
  }

  private log(message: string, payload?: unknown): void {
    if (this.config.debug) {
      console.log("[DouverySessionClient]", message, payload ?? "");
    }
  }
}

export function createSessionClient(
  config: SessionClientConfig = {},
): DouverySessionClient {
  return new DouverySessionClient(config);
}

export async function getSession(
  config: SessionClientConfig = {},
  options: GetSessionOptions = {},
): Promise<SessionState> {
  const client = createSessionClient(config);
  return client.getSession(options);
}

export async function logout(
  config: SessionClientConfig = {},
  options: LogoutOptions = {},
): Promise<void> {
  const client = createSessionClient(config);
  return client.logout(options);
}

export async function switchAccount(
  accountId: string,
  config: SessionClientConfig = {},
  options: SwitchAccountOptions = {},
): Promise<SessionState> {
  const client = createSessionClient(config);
  return client.switchAccount(accountId, options);
}
