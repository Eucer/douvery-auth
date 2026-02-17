import { decodeJwtClaims } from "../jwt";
import type { JwtClaimsBase } from "../jwt";
import type {
  CookieAdapter,
  CookieSetOptions,
  CreateSessionTokenResolverOptions,
  SessionTokenResolver,
} from "./types";
import {
  DEFAULT_SESSION_TOKEN_CACHE_TTL_FACTOR,
  DEFAULT_SESSION_TOKEN_CACHE_TTL_MAX_MS,
  DEFAULT_SESSION_TOKEN_CACHE_TTL_MIN_MS,
  DEFAULT_SESSION_TOKEN_FALLBACK_CACHE_TTL_MS,
  DEFAULT_SESSION_TOKEN_FETCH_TIMEOUT_MS,
} from "./constants";
import { fetchWithTimeout, hasDefinitiveSessionFailure } from "./utils";

interface CachedToken {
  token: string;
  expiresAt: number;
  jwtExp?: number;
}

const DEFAULT_TOKEN_ENDPOINT = "/token";
const DEFAULT_DESTROY_ENDPOINT = "/destroy";

function joinPath(baseUrl: string, path: string): string {
  return `${baseUrl.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
}

function shortSessionId(sessionId?: string): string {
  if (!sessionId) return "no-session";
  return sessionId.length > 12
    ? `${sessionId.slice(0, 8)}...${sessionId.slice(-4)}`
    : sessionId;
}

function computeCacheTTL(
  jwtExp: number | undefined,
  serverExpiresIn: number | undefined,
  options: Required<
    Pick<
      CreateSessionTokenResolverOptions,
      | "fallbackCacheTtlMs"
      | "cacheTtlMinMs"
      | "cacheTtlMaxMs"
      | "cacheTtlFactor"
    >
  >,
): number {
  if (serverExpiresIn && serverExpiresIn > 0) {
    return Math.min(
      Math.max(
        serverExpiresIn * options.cacheTtlFactor * 1000,
        options.cacheTtlMinMs,
      ),
      options.cacheTtlMaxMs,
    );
  }

  if (jwtExp) {
    const remainingMs = jwtExp * 1000 - Date.now();
    if (remainingMs > 0) {
      return Math.min(
        Math.max(remainingMs * options.cacheTtlFactor, options.cacheTtlMinMs),
        options.cacheTtlMaxMs,
      );
    }
  }

  return options.fallbackCacheTtlMs;
}

function getJwtExp(token: string): number | undefined {
  try {
    const claims = decodeJwtClaims<JwtClaimsBase>(token);
    return claims.exp;
  } catch {
    return undefined;
  }
}

export function createSessionTokenResolver(
  options: CreateSessionTokenResolverOptions,
): SessionTokenResolver {
  if (!options.sessionApiUrl) {
    throw new Error("[SessionTokenResolver] sessionApiUrl is required");
  }

  if (!options.cookieName) {
    throw new Error("[SessionTokenResolver] cookieName is required");
  }

  const fetchImpl = options.fetchImpl ?? fetch;

  const cfg = {
    secureCookies: options.secureCookies ?? true,
    tokenEndpoint: options.tokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT,
    destroyEndpoint: options.destroyEndpoint ?? DEFAULT_DESTROY_ENDPOINT,
    fetchTimeoutMs:
      options.fetchTimeoutMs ?? DEFAULT_SESSION_TOKEN_FETCH_TIMEOUT_MS,
    fallbackCacheTtlMs:
      options.fallbackCacheTtlMs ?? DEFAULT_SESSION_TOKEN_FALLBACK_CACHE_TTL_MS,
    cacheTtlMinMs:
      options.cacheTtlMinMs ?? DEFAULT_SESSION_TOKEN_CACHE_TTL_MIN_MS,
    cacheTtlMaxMs:
      options.cacheTtlMaxMs ?? DEFAULT_SESSION_TOKEN_CACHE_TTL_MAX_MS,
    cacheTtlFactor:
      options.cacheTtlFactor ?? DEFAULT_SESSION_TOKEN_CACHE_TTL_FACTOR,
  };

  const cookieCache = new WeakMap<CookieAdapter, CachedToken>();
  const pendingByCookie = new WeakMap<
    CookieAdapter,
    Promise<string | undefined>
  >();
  const tokenCacheBySessionId = new Map<string, CachedToken>();
  const pendingBySessionId = new Map<string, Promise<string | undefined>>();

  function getSessionId(cookies: CookieAdapter): string | undefined {
    return cookies.get(options.cookieName);
  }

  function setSessionCookie(sessionId: string, cookies: CookieAdapter): void {
    const cookieOptions: CookieSetOptions = {
      path: "/",
      httpOnly: true,
      secure: cfg.secureCookies,
      sameSite: "lax",
    };

    if (options.cookieDomain) {
      (cookieOptions as CookieSetOptions & { domain?: string }).domain =
        options.cookieDomain;
    }

    cookies.set(options.cookieName, sessionId, cookieOptions);
  }

  function hasSession(cookies: CookieAdapter): boolean {
    return !!getSessionId(cookies);
  }

  function clearSessionCookie(cookies: CookieAdapter): void {
    const currentSessionId = getSessionId(cookies);
    if (currentSessionId) {
      tokenCacheBySessionId.delete(currentSessionId);
      pendingBySessionId.delete(currentSessionId);
    }

    const cookieOptions: CookieSetOptions = {
      path: "/",
      httpOnly: true,
      secure: cfg.secureCookies,
      sameSite: "lax",
      maxAge: 0,
    };

    if (options.cookieDomain) {
      (cookieOptions as CookieSetOptions & { domain?: string }).domain =
        options.cookieDomain;
    }

    cookies.set(options.cookieName, "", cookieOptions);
    cookieCache.delete(cookies);
    pendingByCookie.delete(cookies);
  }

  function invalidateAccessTokenCache(cookies: CookieAdapter): void {
    const sessionId = getSessionId(cookies);
    if (sessionId) {
      tokenCacheBySessionId.delete(sessionId);
      pendingBySessionId.delete(sessionId);
    }

    cookieCache.delete(cookies);
    pendingByCookie.delete(cookies);

    options.log?.("cache:invalidated", {
      sessionId: shortSessionId(sessionId),
    });
  }

  async function requestSessionToken(
    sessionId: string,
    cookies: CookieAdapter,
  ): Promise<string | undefined> {
    const startedAt = Date.now();

    options.log?.("request:start /api/session/token", {
      sessionId: shortSessionId(sessionId),
    });

    try {
      const response = await fetchWithTimeout(
        joinPath(options.sessionApiUrl, cfg.tokenEndpoint),
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(options.defaultHeaders ?? {}),
          },
          body: JSON.stringify({ session_id: sessionId }),
        },
        cfg.fetchTimeoutMs,
      );

      if (!response.ok) {
        const errorText = await response.text().catch(() => "");
        options.log?.("request:failed /api/session/token", {
          sessionId: shortSessionId(sessionId),
          status: response.status,
          durationMs: Date.now() - startedAt,
          errorText,
        });

        const isDefinitiveFailure = hasDefinitiveSessionFailure(
          response.status,
          errorText,
        );

        if (isDefinitiveFailure) {
          clearSessionCookie(cookies);
          return undefined;
        }

        if (options.debug && !options.defaultHeaders?.["X-Client-Id"]) {
          options.onMissingAuthHeaders?.();
        }

        return undefined;
      }

      const data = (await response.json()) as {
        access_token?: string;
        expires_in?: number;
      };

      if (!data.access_token) {
        options.log?.("request:empty-token /api/session/token", {
          sessionId: shortSessionId(sessionId),
          durationMs: Date.now() - startedAt,
        });
        return undefined;
      }

      const jwtExp = getJwtExp(data.access_token);
      const ttl = computeCacheTTL(jwtExp, data.expires_in, cfg);

      const cachedToken: CachedToken = {
        token: data.access_token,
        expiresAt: Date.now() + ttl,
        jwtExp,
      };

      cookieCache.set(cookies, cachedToken);
      tokenCacheBySessionId.set(sessionId, cachedToken);

      options.log?.("request:success /api/session/token", {
        sessionId: shortSessionId(sessionId),
        durationMs: Date.now() - startedAt,
        cacheTtlMs: ttl,
        jwtExp,
      });

      return data.access_token;
    } catch (error) {
      options.log?.("request:error /api/session/token", {
        sessionId: shortSessionId(sessionId),
        durationMs: Date.now() - startedAt,
        errorName: error instanceof Error ? error.name : "unknown",
      });
      return undefined;
    }
  }

  async function getAccessToken(
    cookies: CookieAdapter,
  ): Promise<string | undefined> {
    const sessionId = getSessionId(cookies);
    if (!sessionId) {
      options.log?.("session:missing cookie");
      return undefined;
    }

    const cachedBySession = tokenCacheBySessionId.get(sessionId);
    if (cachedBySession && cachedBySession.expiresAt > Date.now()) {
      cookieCache.set(cookies, cachedBySession);
      options.log?.("cache:hit tokenCacheBySessionId", {
        sessionId: shortSessionId(sessionId),
      });
      return cachedBySession.token;
    }

    if (cachedBySession && cachedBySession.expiresAt <= Date.now()) {
      tokenCacheBySessionId.delete(sessionId);
      options.log?.("cache:expired tokenCacheBySessionId", {
        sessionId: shortSessionId(sessionId),
      });
    }

    const cachedByCookie = cookieCache.get(cookies);
    if (cachedByCookie && cachedByCookie.expiresAt > Date.now()) {
      options.log?.("cache:hit tokenCache");
      return cachedByCookie.token;
    }

    if (cachedByCookie && cachedByCookie.expiresAt <= Date.now()) {
      options.log?.("cache:expired tokenCache");
      cookieCache.delete(cookies);
    }

    const pendingCookie = pendingByCookie.get(cookies);
    if (pendingCookie) {
      options.log?.("dedup:join pendingResolution");
      return pendingCookie;
    }

    const pendingSession = pendingBySessionId.get(sessionId);
    if (pendingSession) {
      options.log?.("dedup:join pendingResolutionBySessionId", {
        sessionId: shortSessionId(sessionId),
      });
      return pendingSession;
    }

    const request = requestSessionToken(sessionId, cookies);
    pendingByCookie.set(cookies, request);
    pendingBySessionId.set(sessionId, request);

    try {
      return await request;
    } finally {
      pendingByCookie.delete(cookies);
      pendingBySessionId.delete(sessionId);
    }
  }

  function getAccessTokenSync(cookies: CookieAdapter): string | undefined {
    const sessionId = getSessionId(cookies);

    if (sessionId) {
      const cachedBySession = tokenCacheBySessionId.get(sessionId);
      if (cachedBySession && cachedBySession.expiresAt > Date.now()) {
        return cachedBySession.token;
      }
    }

    const cachedByCookie = cookieCache.get(cookies);
    if (cachedByCookie && cachedByCookie.expiresAt > Date.now()) {
      return cachedByCookie.token;
    }

    return undefined;
  }

  async function destroySession(cookies: CookieAdapter): Promise<void> {
    const sessionId = getSessionId(cookies);

    if (sessionId) {
      try {
        await fetchWithTimeout(
          joinPath(options.sessionApiUrl, cfg.destroyEndpoint),
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              ...(options.defaultHeaders ?? {}),
            },
            body: JSON.stringify({ session_id: sessionId }),
          },
          cfg.fetchTimeoutMs,
        );
      } catch {
        // Intentionally ignore destroy network errors and clear local cookie anyway
      }
    }

    clearSessionCookie(cookies);
  }

  return {
    setSessionCookie,
    getSessionId,
    hasSession,
    clearSessionCookie,
    invalidateAccessTokenCache,
    getAccessToken,
    getAccessTokenSync,
    destroySession,
  };
}
