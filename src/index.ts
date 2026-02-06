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
  MemoryStorage,
  LocalStorage,
  SessionStorage,
  CookieStorage,
  TokenManager,
  STORAGE_KEYS,
} from "./storage";
