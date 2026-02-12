/**
 * @douvery/auth - Session Types
 * Framework-agnostic opaque session resolution types
 */

// ============================================================================
// Configuration
// ============================================================================

/** Configuration for the session resolver factory */
export interface SessionResolverConfig {
  /** Auth server session API base URL (e.g. "http://localhost:9924/api/session") */
  sessionApiUrl: string;

  // ── Authentication: choose ONE method ──

  /**
   * Internal service name for IdP UI auth via X-Douvery-Internal-Service header.
   * Used by the IdP's own UI (like accounts.google.com) — NOT an OAuth client.
   * Requires internalServiceSecret.
   */
  internalServiceName?: string;

  /**
   * HMAC secret for internal service auth.
   * Signs X-Douvery-Internal-Signature: HMAC-SHA256(timestamp:serviceName, secret).
   * Used together with internalServiceName.
   */
  internalServiceSecret?: string;

  /**
   * OAuth Client ID for consumer app auth via X-Client-Id header.
   * For apps that ARE OAuth clients (douvery-web, center, mobile).
   */
  clientId?: string;

  /**
   * OAuth Client Secret for consumer app auth via X-Client-Secret header.
   * Used together with clientId. Validated against oauth_clients table (Argon2).
   */
  clientSecret?: string;

  /** Cookie name for the session ID (e.g. "douvery-session") */
  cookieName: string;

  /** Session cookie max age in seconds @default 2592000 (30 days) */
  cookieMaxAge?: number;

  /** Whether cookies should use the 'secure' flag @default true */
  secureCookies?: boolean;

  /** Timeout for lightweight session API calls like /token (ms) @default 3000 */
  fetchTimeoutMs?: number;

  /** Timeout for heavy session API calls like /refresh (ms) @default 8000 */
  refreshTimeoutMs?: number;

  /** Fallback cache TTL when JWT exp cannot be parsed (ms) @default 30000 */
  fallbackCacheTtlMs?: number;

  /** Enable debug logging @default false */
  debug?: boolean;

  /** Custom logger implementation. Defaults to console when debug is true. */
  logger?: SessionLogger;
}

// ============================================================================
// Cookie abstraction
// ============================================================================

/**
 * Minimal cookie adapter interface.
 * Each framework implements this for its own cookie API (Qwik, Next.js, Express, etc).
 *
 * The resolver uses the adapter object reference as a WeakMap key for per-request
 * caching. Ensure the SAME adapter instance is used for all calls within a single
 * request to benefit from deduplication and caching.
 */
export interface CookieAdapter {
  /** Read a cookie value by name. Returns undefined if not found. */
  get(name: string): string | undefined;

  /** Set a cookie with the given name, value, and options. */
  set(name: string, value: string, options: CookieSetOptions): void;
}

/** Options for setting a cookie (standard HTTP cookie attributes) */
export interface CookieSetOptions {
  path?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "strict" | "lax" | "none";
  maxAge?: number;
}

// ============================================================================
// Result types
// ============================================================================

/**
 * Result of a refresh attempt. Callers MUST distinguish between:
 * - 'success': tokens refreshed, cache invalidated — proceed normally
 * - 'definitive_failure': server confirmed session is dead (401/404) — safe to clear cookie
 * - 'transient_failure': timeout/network/500 — session may still be valid, DON'T clear cookie
 */
export type RefreshResult =
  | "success"
  | "definitive_failure"
  | "transient_failure";

// ============================================================================
// Logger
// ============================================================================

export interface SessionLogger {
  debug(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
}

// ============================================================================
// Resolver interface
// ============================================================================

/** The public API returned by createSessionResolver() */
export interface SessionResolver {
  /**
   * Resolve opaque session to JWT access_token (async).
   * Uses per-request caching and deduplication.
   * Returns the JWT even if expired — the caller handles refresh.
   */
  getAccessToken(cookies: CookieAdapter): Promise<string | undefined>;

  /**
   * Synchronous access to cached token (for sync header builders).
   * Returns cached value only — NO network call.
   */
  getAccessTokenSync(cookies: CookieAdapter): string | undefined;

  /**
   * Refresh session tokens via auth server.
   * Triggers full token rotation. Deduplicates concurrent refresh calls
   * across all requests for the same session_id.
   */
  refreshSession(cookies: CookieAdapter): Promise<RefreshResult>;

  /** Destroy session on auth server and clear local cookie. */
  destroySession(cookies: CookieAdapter): Promise<void>;

  /** Save session ID in an HttpOnly cookie after OAuth callback. */
  setSessionCookie(sessionId: string, cookies: CookieAdapter): void;

  /** Read session ID from cookie. */
  getSessionId(cookies: CookieAdapter): string | undefined;

  /** Check if user has an active session cookie. */
  hasSession(cookies: CookieAdapter): boolean;

  /**
   * Clear session cookie and invalidate cached token.
   * Sets an expired cookie to ensure the browser removes it.
   */
  clearSessionCookie(cookies: CookieAdapter): void;
}
