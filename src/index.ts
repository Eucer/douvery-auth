/**
 * @douvery/auth - Session-based auth SDK
 * Browser stores only an HttpOnly session cookie.
 */

export {
  DouverySessionClient,
  createSessionClient,
  getSession,
  logout,
  switchAccount,
} from "./client";

export type {
  SessionClientConfig,
  SessionStatus,
  SessionState,
  SessionUser,
  SessionPayload,
  SessionErrorCode,
  SessionEvent,
  SessionEventHandler,
  GetSessionOptions,
  LogoutOptions,
  SwitchAccountOptions,
} from "./types";

export { SessionError } from "./types";

export { createCurrentUserResolver } from "./current-user";
export type {
  CreateCurrentUserResolverOptions,
  CurrentUserResolver,
} from "./current-user";

export {
  decodeJwtClaims,
  isJwtExpiredFromClaims,
  isJwtExpired,
  getJwtTimeRemaining,
  getJwtSubject,
  verifyJwtAudience,
} from "./jwt";

export type { JwtClaimsBase } from "./jwt";

export type {
  CookieAdapter,
  CookieSetOptions,
  SessionServiceConfig,
  RequireAuthOptions,
  RequireAuthResult,
  SessionService,
} from "./session/types";

export {
  createSessionUserInfoResolver,
  createSessionTokenResolver,
  fetchWithTimeout,
  hasDefinitiveSessionFailure,
  DEFAULT_SESSION_TOKEN_FETCH_TIMEOUT_MS,
  DEFAULT_SESSION_TOKEN_FALLBACK_CACHE_TTL_MS,
  DEFAULT_SESSION_TOKEN_CACHE_TTL_MIN_MS,
  DEFAULT_SESSION_TOKEN_CACHE_TTL_MAX_MS,
  DEFAULT_SESSION_TOKEN_CACHE_TTL_FACTOR,
  DEFAULT_SESSION_USERINFO_CACHE_TTL_MS,
} from "./session";

export type {
  SessionTokenResolverLogContext,
  CreateSessionTokenResolverOptions,
  SessionTokenResolver,
  SessionUserInfoFailure,
  SessionUserInfoFetchResult,
  InvalidSessionContext,
  CreateSessionUserInfoResolverOptions,
} from "./session";

export {
  DEFAULT_DANGEROUS_REDIRECT_PATTERNS,
  containsDangerousRedirectCharacters,
  isAllowedRedirectUrl,
  sanitizeRedirectUrl,
  buildSafeRedirectUrl,
  extractRedirectParam,
} from "./security";

export type { RedirectSecurityOptions } from "./security";

export {
  DOUVERY_ALLOWED_REDIRECT_DOMAINS,
  createDouveryRedirectSecurityOptions,
} from "./security";

export {
  createAuthUrl,
  createLoginUrl,
  createSelectAccountUrl,
  createLogoutUrl,
  createVerifyAccountUrl,
  createUpgradeAccountUrl,
} from "./auth-web";

export type {
  AuthBaseOptions,
  AuthUrlOptions,
  LoginUrlOptions,
  SelectAccountUrlOptions,
  LogoutUrlOptions,
  VerifyAccountUrlOptions,
  UpgradeAccountUrlOptions,
} from "./auth-web";
