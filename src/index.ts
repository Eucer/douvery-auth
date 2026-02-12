/**
 * @douvery/auth - Core Package
 * OAuth 2.0/OIDC client for Douvery authentication
 */

// Client
export { DouveryAuthClient, createDouveryAuth } from "./client";

// Types
export type {
  DouveryAuthConfig,
  TokenSet,
  TokenInfo,
  User,
  AuthState,
  AuthStatus,
  AuthEvent,
  AuthEventHandler,
  AuthErrorCode,
  OIDCDiscovery,
  CallbackResult,
  LoginOptions,
  LogoutOptions,
  DecodedIdToken,
  PKCEPair,
  TokenStorage,
  StorageKeys,
  // Navigation types
  AuthNavigationOptions,
  SelectAccountOptions,
  RegisterOptions,
  RecoverAccountOptions,
  VerifyAccountOptions,
  UpgradeAccountOptions,
  SetupPasskeyOptions,
  SetupAddressOptions,
  AddAccountOptions,
  RevokeTokenOptions,
  AuthUrl,
} from "./types";

export { AuthError } from "./types";

// PKCE utilities
export {
  generateCodeVerifier,
  generateCodeChallenge,
  generateState,
  generateNonce,
  generatePKCEPair,
  verifyCodeChallenge,
  decodeJWT,
  isTokenExpired,
  getTokenExpiration,
  base64UrlEncode,
  base64UrlDecode,
} from "./pkce";

// Storage
export {
  createStorage,
  createServerBridgedStorage,
  MemoryStorage,
  LocalStorage,
  SessionStorage,
  CookieStorage,
  TokenManager,
  STORAGE_KEYS,
} from "./storage";
export type { ServerBridgedStorageOptions } from "./storage";

// Session types (re-exported for convenience; full module at @douvery/auth/session)
export type {
  SessionResolverConfig,
  CookieAdapter,
  CookieSetOptions,
  RefreshResult,
  SessionLogger,
  SessionResolver,
} from "./session/types";
