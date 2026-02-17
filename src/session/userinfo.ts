import { hasDefinitiveSessionFailure } from "./utils";
import { DEFAULT_SESSION_USERINFO_CACHE_TTL_MS } from "./constants";

export interface SessionUserInfoFailure {
  status: number;
  errorText: string;
}

export interface SessionUserInfoFetchResult<TUserInfo> {
  userInfo: TUserInfo | null;
  failure?: SessionUserInfoFailure;
}

export interface InvalidSessionContext {
  userInfoUrl: string;
  hasSessionId: boolean;
  fallbackStatus: number;
  fallbackErrorText: string;
}

export interface CreateSessionUserInfoResolverOptions<
  TClaims extends { sub?: string; sid?: string },
  TUserInfo,
  TSessionState = unknown,
> {
  sessionApiUrl: string;
  authWebUrl?: string;
  explicitUserInfoUrl?: string;
  sessionApiHeaders?: Record<string, string>;
  cacheTtlMs?: number;
  debug?: boolean;
  fetchImpl?: typeof fetch;
  mapSessionStateToUserInfo: (
    sessionState: TSessionState,
    claims: TClaims,
  ) => TUserInfo | null;
  getSessionId?: (
    claims: TClaims,
    sessionIdFromCookie?: string,
  ) => string | undefined;
  getDedupKey?: (
    accessToken: string,
    claims: TClaims,
    sessionIdFromCookie?: string,
  ) => string;
  shouldThrowInvalidSession?: (failure: SessionUserInfoFailure) => boolean;
  throwInvalidSession?: (context: InvalidSessionContext) => never | void;
  log?: (message: string, context?: Record<string, unknown>) => void;
}

function shortKey(value?: string): string {
  if (!value) return "none";
  return value.length > 16
    ? `${value.slice(0, 8)}...${value.slice(-4)}`
    : value;
}

function defaultGetDedupKey<TClaims extends { sub?: string; sid?: string }>(
  accessToken: string,
  claims: TClaims,
  sessionIdFromCookie?: string,
): string {
  return (
    sessionIdFromCookie || claims.sid || claims.sub || accessToken.slice(0, 24)
  );
}

function defaultGetSessionId<TClaims extends { sid?: string }>(
  claims: TClaims,
  sessionIdFromCookie?: string,
): string | undefined {
  return sessionIdFromCookie || claims.sid;
}

function defaultShouldThrowInvalidSession(
  failure: SessionUserInfoFailure,
): boolean {
  return hasDefinitiveSessionFailure(failure.status, failure.errorText);
}

function deriveUserInfoUrl(sessionApiUrl: string, authWebUrl?: string): string {
  try {
    const sessionApi = new URL(sessionApiUrl);
    return `${sessionApi.origin}/api/oauth/userinfo`;
  } catch {
    return authWebUrl ? `${authWebUrl}/oauth/userinfo` : "/oauth/userinfo";
  }
}

export function createSessionUserInfoResolver<
  TClaims extends { sub?: string; sid?: string },
  TUserInfo,
  TSessionState = unknown,
>(
  options: CreateSessionUserInfoResolverOptions<
    TClaims,
    TUserInfo,
    TSessionState
  >,
) {
  const cacheTtlMs =
    options.cacheTtlMs ?? DEFAULT_SESSION_USERINFO_CACHE_TTL_MS;
  const fetchImpl = options.fetchImpl ?? fetch;
  const getSessionId = options.getSessionId ?? defaultGetSessionId<TClaims>;
  const getDedupKey = options.getDedupKey ?? defaultGetDedupKey<TClaims>;
  const shouldThrowInvalidSession =
    options.shouldThrowInvalidSession ?? defaultShouldThrowInvalidSession;
  const log = options.log;

  const unavailableUserInfoUrls = new Set<string>();
  const inFlightSessionStateUserInfo = new Map<
    string,
    Promise<TUserInfo | null>
  >();
  const sessionStateUserInfoCache = new Map<
    string,
    { userInfo: TUserInfo; expiresAt: number }
  >();

  const requestSessionState = async (
    claims: TClaims,
    sessionIdFromCookie?: string,
  ): Promise<SessionUserInfoFetchResult<TUserInfo>> => {
    const sessionId = getSessionId(claims, sessionIdFromCookie);
    if (!options.sessionApiUrl || !sessionId) return { userInfo: null };

    const startedAt = Date.now();
    log?.("request:start /api/session/accounts/state", {
      sessionId: shortKey(sessionId),
      userId: claims.sub,
    });

    const response = await fetchImpl(
      `${options.sessionApiUrl}/accounts/state`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(options.sessionApiHeaders ?? {}),
        },
        body: JSON.stringify({ session_id: sessionId }),
      },
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => "");
      log?.("request:failed /api/session/accounts/state", {
        sessionId: shortKey(sessionId),
        status: response.status,
        durationMs: Date.now() - startedAt,
      });

      if (options.debug) {
        console.warn("[Auth] Session accounts/state fallback failed", {
          status: response.status,
          errorText,
          sessionId,
        });
      }

      return {
        userInfo: null,
        failure: { status: response.status, errorText },
      };
    }

    const data = (await response.json()) as TSessionState;
    log?.("request:success /api/session/accounts/state", {
      sessionId: shortKey(sessionId),
      durationMs: Date.now() - startedAt,
    });

    return { userInfo: options.mapSessionStateToUserInfo(data, claims) };
  };

  const requestSessionStateDedup = async (
    accessToken: string,
    claims: TClaims,
    sessionIdFromCookie?: string,
  ): Promise<SessionUserInfoFetchResult<TUserInfo>> => {
    const dedupKey = getDedupKey(accessToken, claims, sessionIdFromCookie);
    const cached = sessionStateUserInfoCache.get(dedupKey);

    if (cached && cached.expiresAt > Date.now()) {
      sessionStateUserInfoCache.set(dedupKey, {
        userInfo: cached.userInfo,
        expiresAt: Date.now() + cacheTtlMs,
      });
      log?.("cache:hit sessionStateUserInfo", { key: shortKey(dedupKey) });
      return { userInfo: cached.userInfo };
    }

    if (cached && cached.expiresAt <= Date.now()) {
      log?.("cache:expired sessionStateUserInfo", { key: shortKey(dedupKey) });
      sessionStateUserInfoCache.delete(dedupKey);
    }

    const pending = inFlightSessionStateUserInfo.get(dedupKey);
    if (pending) {
      log?.("dedup:join inFlightSessionState", { key: shortKey(dedupKey) });
      const userInfo = await pending;
      return { userInfo };
    }

    const request = requestSessionState(claims, sessionIdFromCookie)
      .then((result) => result.userInfo)
      .finally(() => {
        inFlightSessionStateUserInfo.delete(dedupKey);
      });

    inFlightSessionStateUserInfo.set(dedupKey, request);

    try {
      const userInfo = await request;
      if (userInfo) {
        sessionStateUserInfoCache.set(dedupKey, {
          userInfo,
          expiresAt: Date.now() + cacheTtlMs,
        });
        log?.("cache:set sessionStateUserInfo", {
          key: shortKey(dedupKey),
          ttlMs: cacheTtlMs,
        });
      }
      return { userInfo };
    } catch {
      return { userInfo: null };
    }
  };

  const fetchUserInfo = async (
    accessToken: string,
    claims: TClaims,
    sessionIdFromCookie?: string,
  ): Promise<TUserInfo> => {
    const userInfoUrl =
      options.explicitUserInfoUrl ||
      deriveUserInfoUrl(options.sessionApiUrl, options.authWebUrl);

    if (unavailableUserInfoUrls.has(userInfoUrl)) {
      log?.("userinfo:skip-known-404", { userInfoUrl });
      const fallback = await requestSessionStateDedup(
        accessToken,
        claims,
        sessionIdFromCookie,
      );
      if (fallback.userInfo) return fallback.userInfo;
    }

    const response = await fetchImpl(userInfoUrl, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
      },
    });

    if (response.status === 404) {
      log?.("userinfo:404-marked-unavailable", { userInfoUrl });
      unavailableUserInfoUrls.add(userInfoUrl);

      const fallback = await requestSessionStateDedup(
        accessToken,
        claims,
        sessionIdFromCookie,
      );
      if (fallback.userInfo) return fallback.userInfo;

      if (fallback.failure && shouldThrowInvalidSession(fallback.failure)) {
        options.throwInvalidSession?.({
          userInfoUrl,
          hasSessionId: !!getSessionId(claims, sessionIdFromCookie),
          fallbackStatus: fallback.failure.status,
          fallbackErrorText: fallback.failure.errorText,
        });
      }
    }

    if (!response.ok) {
      const errorText = await response.text().catch(() => "");
      throw new Error(
        `Error obteniendo UserInfo: ${response.status} ${errorText}`.trim(),
      );
    }

    return (await response.json()) as TUserInfo;
  };

  return {
    fetchUserInfo,
  };
}
