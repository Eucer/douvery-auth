/**
 * @douvery/auth/session - Session service types
 */

import type { SessionState } from "../types";

export interface CookieAdapter {
  get(name: string): string | undefined;
  set(name: string, value: string, options: CookieSetOptions): void;
}

export interface CookieSetOptions {
  path?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "strict" | "lax" | "none";
  maxAge?: number;
}

export interface SessionServiceConfig {
  sessionApiUrl: string;
  cookieName: string;
  secureCookies?: boolean;
  sessionEndpoint?: string;
  logoutEndpoint?: string;
  switchAccountEndpoint?: string;
  fetchTimeoutMs?: number;
  defaultHeaders?: Record<string, string>;
  debug?: boolean;
}

export interface RequireAuthOptions {
  redirectTo?: string;
}

export type RequireAuthResult =
  | { ok: true; state: SessionState }
  | { ok: false; state: SessionState; redirectTo: string };

export interface SessionService {
  getSession(cookies: CookieAdapter): Promise<SessionState>;
  requireAuth(
    cookies: CookieAdapter,
    options?: RequireAuthOptions,
  ): Promise<RequireAuthResult>;
  logout(cookies: CookieAdapter): Promise<void>;
  switchAccount(
    cookies: CookieAdapter,
    accountId: string,
  ): Promise<SessionState>;
}

export interface SessionTokenResolverLogContext {
  sessionId?: string;
  status?: number;
  durationMs?: number;
  errorText?: string;
  cacheTtlMs?: number;
  jwtExp?: number;
  errorName?: string;
}

export interface CreateSessionTokenResolverOptions {
  sessionApiUrl: string;
  cookieName: string;
  secureCookies?: boolean;
  cookieDomain?: string;
  tokenEndpoint?: string;
  destroyEndpoint?: string;
  fetchTimeoutMs?: number;
  fallbackCacheTtlMs?: number;
  cacheTtlMinMs?: number;
  cacheTtlMaxMs?: number;
  cacheTtlFactor?: number;
  defaultHeaders?: Record<string, string>;
  fetchImpl?: typeof fetch;
  debug?: boolean;
  onMissingAuthHeaders?: () => void;
  log?: (message: string, context?: SessionTokenResolverLogContext) => void;
}

export interface SessionTokenResolver {
  setSessionCookie(sessionId: string, cookies: CookieAdapter): void;
  getSessionId(cookies: CookieAdapter): string | undefined;
  hasSession(cookies: CookieAdapter): boolean;
  clearSessionCookie(cookies: CookieAdapter): void;
  /**
   * Clears in-memory access token cache for the current session (if any)
   * without modifying the session cookie.
   */
  invalidateAccessTokenCache(cookies: CookieAdapter): void;
  getAccessToken(cookies: CookieAdapter): Promise<string | undefined>;
  getAccessTokenSync(cookies: CookieAdapter): string | undefined;
  destroySession(cookies: CookieAdapter): Promise<void>;
}
