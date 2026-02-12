/**
 * @douvery/auth - Session Resolver
 * Factory for creating framework-agnostic opaque session resolvers.
 *
 * Architecture:
 * ┌─────────┐  session_id cookie  ┌──────────────┐    JWT     ┌──────────────┐
 * │ Browser │ ──────────────────▶ │ SSR App      │ ─────────▶ │ Resource     │
 * │         │                     │              │            │ Server       │
 * └─────────┘                     └──────┬───────┘            │ (GraphQL)    │
 *                                        │                    └──────────────┘
 *                                        │ POST /api/session/token
 *                                        ▼
 *                                 ┌──────────────┐
 *                                 │ Auth Server  │
 *                                 │ (Redis)      │
 *                                 └──────────────┘
 *
 * Security:
 * - Browser only sees opaque session_id (256-bit random, base64url)
 * - JWT access_token lives only in Redis + server memory
 * - IdP UI auth: X-Douvery-Internal-Service + HMAC signature (internal trust)
 * - Consumer app auth: X-Client-Id + X-Client-Secret headers (OAuth per-client)
 * - Per-request WeakMap cache prevents duplicate network calls
 * - Cross-request Map<string> dedup prevents refresh token reuse detection
 */

import type {
  SessionResolverConfig,
  CookieAdapter,
  RefreshResult,
  SessionLogger,
  SessionResolver,
} from "./types";
import {
  parseJwtExp,
  computeCacheTTL,
  fetchWithTimeout,
  computeHmac,
} from "./utils";

// ============================================================================
// Defaults & internal helpers
// ============================================================================

const DEFAULTS = {
  cookieMaxAge: 30 * 24 * 60 * 60, // 30 days in seconds
  secureCookies: true,
  fetchTimeoutMs: 3_000,
  refreshTimeoutMs: 8_000,
  fallbackCacheTtlMs: 30_000,
  debug: false,
} as const;

/** Noop logger for when debug is off */
const NOOP_LOGGER: SessionLogger = {
  debug() {},
  warn() {},
  error() {},
};

/** Console-based logger with [Session] prefix */
const CONSOLE_LOGGER: SessionLogger = {
  debug: (...args) => console.log("[Session]", ...args),
  warn: (...args) => console.warn("[Session]", ...args),
  error: (...args) => console.error("[Session]", ...args),
};

/** Token cache entry */
interface CacheEntry {
  token: string;
  expiresAt: number;
  jwtExp?: number;
}

// ============================================================================
// Factory
// ============================================================================

/**
 * Create a session resolver instance.
 *
 * Returns a {@link SessionResolver} with internal state (caches, dedup maps)
 * scoped to this resolver instance. Multiple resolvers can coexist
 * (e.g., for different auth servers or cookie names).
 *
 * @example
 * ```typescript
 * // IdP UI (like accounts.google.com — internal service, NOT an OAuth client)
 * const resolver = createSessionResolver({
 *   sessionApiUrl: 'http://localhost:9924/api/session',
 *   internalServiceName: 'auth-web',
 *   internalServiceSecret: process.env.INTERNAL_SERVICE_SECRET,
 *   cookieName: 'my-session',
 *   debug: process.env.NODE_ENV === 'development',
 * });
 *
 * // Consumer app (OAuth client — douvery-web, center, mobile)
 * const resolver = createSessionResolver({
 *   sessionApiUrl: 'http://localhost:9924/api/session',
 *   clientId: process.env.OAUTH_CLIENT_ID,
 *   clientSecret: process.env.OAUTH_CLIENT_SECRET,
 *   cookieName: 'my-session',
 * });
 *
 * // In a request handler:
 * const token = await resolver.getAccessToken(cookieAdapter);
 * ```
 */
export function createSessionResolver(
  config: SessionResolverConfig,
): SessionResolver {
  // Merge defaults
  const cfg = { ...DEFAULTS, ...config };

  // Configure logger
  const log: SessionLogger =
    cfg.logger ?? (cfg.debug ? CONSOLE_LOGGER : NOOP_LOGGER);

  // Validate required config
  if (!cfg.sessionApiUrl) {
    throw new Error(
      "[Session] sessionApiUrl is required. " +
        "Provide the auth server session API URL.",
    );
  }

  if (!cfg.cookieName) {
    throw new Error(
      "[Session] cookieName is required. " +
        "Provide the cookie name for the session ID.",
    );
  }

  // ============================================================================
  // Internal state (scoped to this resolver instance)
  // ============================================================================

  /**
   * Per-request token cache. WeakMap keyed by CookieAdapter object reference.
   * Each SSR request should reuse the SAME adapter instance for all calls,
   * ensuring per-request caching without cross-request pollution.
   */
  const tokenCache = new WeakMap<CookieAdapter, CacheEntry>();

  /**
   * Pending resolution dedup. Prevents duplicate POST /token calls when
   * multiple routeLoaders in the same SSR request call getAccessToken().
   */
  const pendingResolutions = new WeakMap<
    CookieAdapter,
    Promise<string | undefined>
  >();

  /**
   * Cross-request refresh dedup keyed by session_id string.
   *
   * CRITICAL: Must be keyed by sessionId, NOT by CookieAdapter.
   * Concurrent SSR requests (e.g., SPA hover prefetch) get DIFFERENT
   * adapter objects even though they share the same session_id. Without
   * string-based dedup, concurrent refreshes would trigger refresh token
   * reuse detection and destroy the session.
   *
   * Cleanup: entries are deleted in the finally block of refreshSession().
   */
  const pendingRefreshBySession = new Map<string, Promise<RefreshResult>>();

  // ============================================================================
  // Cookie helpers
  // ============================================================================

  function getSessionId(cookies: CookieAdapter): string | undefined {
    return cookies.get(cfg.cookieName);
  }

  function hasSession(cookies: CookieAdapter): boolean {
    return !!getSessionId(cookies);
  }

  function setSessionCookie(sessionId: string, cookies: CookieAdapter): void {
    cookies.set(cfg.cookieName, sessionId, {
      path: "/",
      httpOnly: true,
      secure: cfg.secureCookies,
      sameSite: "lax",
      maxAge: cfg.cookieMaxAge,
    });
  }

  function clearSessionCookie(cookies: CookieAdapter): void {
    cookies.set(cfg.cookieName, "", {
      path: "/",
      httpOnly: true,
      secure: cfg.secureCookies,
      sameSite: "lax",
      maxAge: 0,
    });
    tokenCache.delete(cookies);
  }

  // ============================================================================
  // Internal: build headers for auth server requests
  // ============================================================================

  function buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    // Method 1: Internal service HMAC (IdP UI)
    if (cfg.internalServiceName && cfg.internalServiceSecret) {
      const timestamp = String(Date.now());
      const message = `${timestamp}:${cfg.internalServiceName}`;
      headers["X-Douvery-Internal-Service"] = cfg.internalServiceName;
      headers["X-Douvery-Internal-Timestamp"] = timestamp;
      headers["X-Douvery-Internal-Signature"] = computeHmac(
        message,
        cfg.internalServiceSecret,
      );
    }
    // Method 2: Per-client OAuth credentials (consumer apps)
    else if (cfg.clientId && cfg.clientSecret) {
      headers["X-Client-Id"] = cfg.clientId;
      headers["X-Client-Secret"] = cfg.clientSecret;
    }

    return headers;
  }

  // ============================================================================
  // Internal: network resolution (session_id -> JWT)
  // ============================================================================

  async function resolveSessionToken(
    sessionId: string,
    cookies: CookieAdapter,
  ): Promise<string | undefined> {
    try {
      const response = await fetchWithTimeout(
        `${cfg.sessionApiUrl}/token`,
        {
          method: "POST",
          headers: buildHeaders(),
          body: JSON.stringify({ session_id: sessionId }),
        },
        cfg.fetchTimeoutMs,
      );

      if (!response.ok) {
        if (response.status === 401 || response.status === 404) {
          log.warn("Session expired or not found:", response.status);
          clearSessionCookie(cookies);
          return undefined;
        }

        const errorText = await response.text().catch(() => "");
        log.error("Token resolution failed:", response.status, errorText);
        return undefined;
      }

      const data = await response.json();

      if (data.access_token) {
        const jwtExp = parseJwtExp(data.access_token);
        const ttl = computeCacheTTL(
          jwtExp,
          data.expires_in,
          cfg.fallbackCacheTtlMs,
        );

        tokenCache.set(cookies, {
          token: data.access_token,
          expiresAt: Date.now() + ttl,
          jwtExp,
        });

        return data.access_token;
      }

      return undefined;
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        log.error("Token resolution timed out after", cfg.fetchTimeoutMs, "ms");
        return undefined;
      }
      log.error("Network error resolving token:", error);
      return undefined;
    }
  }

  // ============================================================================
  // Token resolution (public)
  // ============================================================================

  /**
   * Resolve opaque session to JWT access_token (ASYNC).
   *
   * Uses per-request caching via WeakMap to avoid duplicate network calls.
   *
   * IMPORTANT: Returns the resolved JWT even if it's expired. The caller
   * (e.g., validateAndRefreshTokens) is responsible for checking expiry
   * and triggering refreshSession(). This avoids a race condition where
   * both this function and the caller would attempt concurrent refreshes.
   */
  async function getAccessToken(
    cookies: CookieAdapter,
  ): Promise<string | undefined> {
    // 1. Check resolved cache
    const cached = tokenCache.get(cookies);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.token;
    }

    // 2. Dedup concurrent calls for the same request
    const pending = pendingResolutions.get(cookies);
    if (pending) {
      return pending;
    }

    // 3. Check for session cookie
    const sessionId = getSessionId(cookies);
    if (!sessionId) {
      return undefined;
    }

    // 4. Start async resolution
    const resolution = resolveSessionToken(sessionId, cookies);
    pendingResolutions.set(cookies, resolution);

    try {
      const token = await resolution;

      if (!token) {
        return undefined;
      }

      // Return even if expired — caller handles refresh
      if (cfg.debug) {
        const exp = parseJwtExp(token);
        if (exp && exp * 1000 <= Date.now()) {
          log.debug("Resolved JWT is expired — caller should handle refresh");
        }
      }

      return token;
    } finally {
      pendingResolutions.delete(cookies);
    }
  }

  /**
   * Synchronous access to cached token (for sync header builders).
   * Returns cached value only — NO network call.
   */
  function getAccessTokenSync(cookies: CookieAdapter): string | undefined {
    const cached = tokenCache.get(cookies);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.token;
    }
    return undefined;
  }

  // ============================================================================
  // Session lifecycle
  // ============================================================================

  /** Internal: actual refresh logic, called only once per session via dedup. */
  async function _doRefreshSession(
    cookies: CookieAdapter,
    sessionId: string,
  ): Promise<RefreshResult> {
    try {
      const response = await fetchWithTimeout(
        `${cfg.sessionApiUrl}/refresh`,
        {
          method: "POST",
          headers: buildHeaders(),
          body: JSON.stringify({ session_id: sessionId }),
        },
        cfg.refreshTimeoutMs,
      );

      if (!response.ok) {
        if (response.status === 401 || response.status === 404) {
          log.warn("Session expired during refresh:", response.status);
          clearSessionCookie(cookies);
          return "definitive_failure";
        }

        if (cfg.debug) {
          const errorText = await response.text().catch(() => "");
          log.warn("Refresh returned", response.status, errorText);
        }
        return "transient_failure";
      }

      // Invalidate token cache so next getAccessToken() fetches fresh JWT
      tokenCache.delete(cookies);
      log.debug("Tokens refreshed successfully via session");

      return "success";
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        log.error(
          "Refresh request timed out after",
          cfg.refreshTimeoutMs,
          "ms",
        );
        return "transient_failure";
      }
      log.error("Error refreshing session:", error);
      return "transient_failure";
    }
  }

  /**
   * Refresh session tokens via auth server.
   * Triggers full token rotation (new access + new refresh token in Redis).
   *
   * Deduplicates concurrent refresh calls across ALL requests for the same
   * session. Multiple concurrent SSR requests (SPA hover/prefetch) share
   * the same session_id but have different CookieAdapter objects. Only one
   * actual POST /refresh fires per session — subsequent requests join the
   * same promise.
   */
  async function refreshSession(
    cookies: CookieAdapter,
  ): Promise<RefreshResult> {
    const sessionId = getSessionId(cookies);
    if (!sessionId) {
      return "definitive_failure";
    }

    // Dedup concurrent refresh calls across ALL requests for the same session
    const pendingRefresh = pendingRefreshBySession.get(sessionId);
    if (pendingRefresh) {
      log.debug("Refresh already in progress for session, joining...");
      const result = await pendingRefresh;

      // Invalidate THIS request's token cache
      // (joining request may have stale cache from before the refresh)
      if (result === "success") {
        tokenCache.delete(cookies);
      }

      return result;
    }

    const refreshPromise = _doRefreshSession(cookies, sessionId);
    pendingRefreshBySession.set(sessionId, refreshPromise);

    try {
      return await refreshPromise;
    } finally {
      pendingRefreshBySession.delete(sessionId);
    }
  }

  /**
   * Destroy session on auth server and clear local cookie.
   * Used during logout.
   */
  async function destroySession(cookies: CookieAdapter): Promise<void> {
    const sessionId = getSessionId(cookies);

    if (sessionId) {
      try {
        await fetchWithTimeout(
          `${cfg.sessionApiUrl}/destroy`,
          {
            method: "POST",
            headers: buildHeaders(),
            body: JSON.stringify({ session_id: sessionId }),
          },
          cfg.fetchTimeoutMs,
        );
        log.debug("Session destroyed on auth server");
      } catch (error) {
        log.error("Error destroying session:", error);
        // Continue with local cleanup even if server call fails
      }
    }

    clearSessionCookie(cookies);
  }

  // ============================================================================
  // Public API
  // ============================================================================

  return {
    getAccessToken,
    getAccessTokenSync,
    refreshSession,
    destroySession,
    setSessionCookie,
    getSessionId,
    hasSession,
    clearSessionCookie,
  };
}
