/**
 * @douvery/auth - Session-based Types
 */

export type SessionStatus =
  | "loading"
  | "authenticated"
  | "unauthenticated"
  | "expired";

export interface SessionUser {
  id: string;
  email?: string;
  name?: string;
  picture?: string;
  locale?: string;
  [key: string]: unknown;
}

export interface SessionPayload {
  sessionId?: string;
  issuedAt?: number;
  expiresAt?: number;
  [key: string]: unknown;
}

export interface SessionState {
  status: SessionStatus;
  user: SessionUser | null;
  session: SessionPayload | null;
  error: SessionError | null;
  checkedAt: number | null;
}

export interface SessionClientConfig {
  baseUrl?: string;
  sessionEndpoint?: string;
  logoutEndpoint?: string;
  switchAccountEndpoint?: string;
  fetchImpl?: typeof fetch;
  defaultHeaders?: Record<string, string>;
  /**
   * BroadcastChannel name to sync auth/session changes across browser tabs.
   * - Defaults to a stable channel name when available.
   * - Set to `false` to disable.
   */
  broadcastChannel?: string | false;
  debug?: boolean;
}

export interface GetSessionOptions {
  signal?: AbortSignal;
  bypassCache?: boolean;
}

export interface LogoutOptions {
  signal?: AbortSignal;
}

export interface SwitchAccountOptions {
  signal?: AbortSignal;
}

export type SessionEvent =
  | { type: "SESSION_UPDATED"; state: SessionState }
  | { type: "SESSION_EXPIRED"; state: SessionState }
  | { type: "SESSION_ERROR"; error: SessionError };

export type SessionEventHandler = (event: SessionEvent) => void;

export class SessionError extends Error {
  constructor(
    public code: SessionErrorCode,
    message: string,
    public cause?: unknown,
    public status?: number,
  ) {
    super(message);
    this.name = "SessionError";
  }
}

export type SessionErrorCode =
  | "network_error"
  | "unauthenticated"
  | "session_expired"
  | "forbidden"
  | "invalid_response"
  | "unknown_error";
