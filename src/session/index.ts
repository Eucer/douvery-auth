/**
 * @douvery/auth/session - Server-side session utilities
 */

export { createSessionService, requireAuth } from "./resolver";
export { createSessionUserInfoResolver } from "./userinfo";
export { createSessionTokenResolver } from "./token-resolver";

export type {
  CookieAdapter,
  CookieSetOptions,
  SessionServiceConfig,
  RequireAuthOptions,
  RequireAuthResult,
  SessionService,
  CreateSessionTokenResolverOptions,
  SessionTokenResolver,
  SessionTokenResolverLogContext,
} from "./types";

export type {
  SessionUserInfoFailure,
  SessionUserInfoFetchResult,
  InvalidSessionContext,
  CreateSessionUserInfoResolverOptions,
} from "./userinfo";

export { fetchWithTimeout, hasDefinitiveSessionFailure } from "./utils";
export {
  DEFAULT_SESSION_TOKEN_FETCH_TIMEOUT_MS,
  DEFAULT_SESSION_TOKEN_FALLBACK_CACHE_TTL_MS,
  DEFAULT_SESSION_TOKEN_CACHE_TTL_MIN_MS,
  DEFAULT_SESSION_TOKEN_CACHE_TTL_MAX_MS,
  DEFAULT_SESSION_TOKEN_CACHE_TTL_FACTOR,
  DEFAULT_SESSION_USERINFO_CACHE_TTL_MS,
} from "./constants";
