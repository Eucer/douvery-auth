import type {
  CookieAdapter,
  RequireAuthOptions,
  RequireAuthResult,
  SessionService,
  SessionServiceConfig,
} from "./types";
import type { SessionState } from "../types";
import { SessionError } from "../types";
import { fetchWithTimeout, hasDefinitiveSessionFailure } from "./utils";

const DEFAULTS = {
  secureCookies: true,
  sessionEndpoint: "/session",
  logoutEndpoint: "/logout",
  switchAccountEndpoint: "/switch-account",
  fetchTimeoutMs: 3000,
  debug: false,
} as const;

interface SessionApiPayload {
  status?: SessionState["status"];
  user?: SessionState["user"];
  session?: SessionState["session"];
}

export function createSessionService(
  config: SessionServiceConfig,
): SessionService {
  const cfg = { ...DEFAULTS, ...config };

  if (!cfg.sessionApiUrl) {
    throw new Error("[SessionService] sessionApiUrl is required");
  }

  if (!cfg.cookieName) {
    throw new Error("[SessionService] cookieName is required");
  }

  function getSessionId(cookies: CookieAdapter): string | undefined {
    return cookies.get(cfg.cookieName);
  }

  function clearSessionCookie(cookies: CookieAdapter): void {
    cookies.set(cfg.cookieName, "", {
      path: "/",
      httpOnly: true,
      secure: cfg.secureCookies,
      sameSite: "lax",
      maxAge: 0,
    });
  }

  async function request(path: string, init: RequestInit): Promise<Response> {
    const url = `${cfg.sessionApiUrl}${path}`;
    return fetchWithTimeout(
      url,
      {
        credentials: "include",
        ...init,
        headers: {
          "Content-Type": "application/json",
          ...(cfg.defaultHeaders ?? {}),
          ...(init.headers ?? {}),
        },
      },
      cfg.fetchTimeoutMs,
    );
  }

  function normalizeState(payload?: SessionApiPayload): SessionState {
    const status =
      payload?.status ?? (payload?.user ? "authenticated" : "unauthenticated");
    return {
      status,
      user: payload?.user ?? null,
      session: payload?.session ?? null,
      error: null,
      checkedAt: Date.now(),
    };
  }

  async function getSession(cookies: CookieAdapter): Promise<SessionState> {
    const sessionId = getSessionId(cookies);
    if (!sessionId) {
      return {
        status: "unauthenticated",
        user: null,
        session: null,
        error: null,
        checkedAt: Date.now(),
      };
    }

    try {
      const response = await request(cfg.sessionEndpoint, {
        method: "POST",
        body: JSON.stringify({ sessionId }),
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => "");

        if (hasDefinitiveSessionFailure(response.status, errorText)) {
          clearSessionCookie(cookies);
          return {
            status: "unauthenticated",
            user: null,
            session: null,
            error: null,
            checkedAt: Date.now(),
          };
        }

        if (
          response.status === 403 ||
          response.status === 419 ||
          response.status === 440
        ) {
          return {
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
          };
        }

        if (cfg.debug) {
          console.warn(
            "[SessionService] non-definitive session resolution error",
            {
              status: response.status,
              errorText,
            },
          );
        }

        return {
          status: "unauthenticated",
          user: null,
          session: null,
          error: new SessionError(
            "unknown_error",
            "Unable to resolve session",
            undefined,
            response.status,
          ),
          checkedAt: Date.now(),
        };
      }

      const payload = (await response.json()) as SessionApiPayload;
      return normalizeState(payload);
    } catch (error) {
      return {
        status: "unauthenticated",
        user: null,
        session: null,
        error: new SessionError(
          "network_error",
          "Session request failed",
          error,
        ),
        checkedAt: Date.now(),
      };
    }
  }

  async function requireAuth(
    cookies: CookieAdapter,
    options: RequireAuthOptions = {},
  ): Promise<RequireAuthResult> {
    const state = await getSession(cookies);
    if (state.status === "authenticated") {
      return { ok: true, state };
    }

    return {
      ok: false,
      state,
      redirectTo: options.redirectTo ?? "/auth/login",
    };
  }

  async function logout(cookies: CookieAdapter): Promise<void> {
    const sessionId = getSessionId(cookies);

    if (sessionId) {
      try {
        await request(cfg.logoutEndpoint, {
          method: "POST",
          body: JSON.stringify({ sessionId }),
        });
      } catch (error) {
        if (cfg.debug) {
          console.error("[SessionService] logout request failed", error);
        }
      }
    }

    clearSessionCookie(cookies);
  }

  async function switchAccount(
    cookies: CookieAdapter,
    accountId: string,
  ): Promise<SessionState> {
    const sessionId = getSessionId(cookies);
    if (!sessionId) {
      return {
        status: "unauthenticated",
        user: null,
        session: null,
        error: null,
        checkedAt: Date.now(),
      };
    }

    if (!accountId?.trim()) {
      return {
        status: "unauthenticated",
        user: null,
        session: null,
        error: new SessionError("invalid_response", "accountId is required"),
        checkedAt: Date.now(),
      };
    }

    try {
      const response = await request(cfg.switchAccountEndpoint, {
        method: "POST",
        body: JSON.stringify({ sessionId, accountId }),
      });

      if (!response.ok) {
        return {
          status: "unauthenticated",
          user: null,
          session: null,
          error: new SessionError(
            "unknown_error",
            "Switch account failed",
            undefined,
            response.status,
          ),
          checkedAt: Date.now(),
        };
      }

      const payload = (await response.json()) as SessionApiPayload;
      return normalizeState(payload);
    } catch (error) {
      return {
        status: "unauthenticated",
        user: null,
        session: null,
        error: new SessionError(
          "network_error",
          "Switch account request failed",
          error,
        ),
        checkedAt: Date.now(),
      };
    }
  }

  return {
    getSession,
    requireAuth,
    logout,
    switchAccount,
  };
}

export async function requireAuth(
  service: SessionService,
  cookies: CookieAdapter,
  options?: RequireAuthOptions,
): Promise<RequireAuthResult> {
  return service.requireAuth(cookies, options);
}
