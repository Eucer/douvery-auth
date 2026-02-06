/**
 * @douvery/auth - Core Types
 * OAuth 2.0/OIDC type definitions
 */

// ============================================
// Configuration Types
// ============================================

export interface DouveryAuthConfig {
  /** OAuth Client ID */
  clientId: string;
  /** Authorization server base URL @default "https://auth.douvery.com" */
  issuer?: string;
  /** Redirect URI after authentication */
  redirectUri: string;
  /** Post-logout redirect URI */
  postLogoutRedirectUri?: string;
  /** OAuth scopes to request @default ["openid", "profile", "email"] */
  scopes?: string[];
  /** Token storage strategy @default "localStorage" */
  storage?: "localStorage" | "sessionStorage" | "memory" | "cookie";
  /** Custom storage implementation */
  customStorage?: TokenStorage;
  /** Auto-refresh tokens before expiry @default true */
  autoRefresh?: boolean;
  /** Seconds before expiry to trigger refresh @default 60 */
  refreshThreshold?: number;
  /** Enable debug logging @default false */
  debug?: boolean;
}

// ============================================
// Token Types
// ============================================

export interface TokenSet {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

export interface TokenInfo {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresAt: number;
  tokenType: string;
  scope: string[];
}

export interface DecodedIdToken {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  auth_time?: number;
  nonce?: string;
  acr?: string;
  amr?: string[];
  azp?: string;
  at_hash?: string;
  c_hash?: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: {
    formatted?: string;
    street_address?: string;
    locality?: string;
    region?: string;
    postal_code?: string;
    country?: string;
  };
  updated_at?: number;
  [key: string]: unknown;
}

// ============================================
// User Types
// ============================================

export interface User {
  id: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  firstName?: string;
  lastName?: string;
  picture?: string;
  phoneNumber?: string;
  phoneNumberVerified?: boolean;
  locale?: string;
  [key: string]: unknown;
}

// ============================================
// Auth State Types
// ============================================

export type AuthStatus = "loading" | "authenticated" | "unauthenticated";

export interface AuthState {
  status: AuthStatus;
  user: User | null;
  tokens: TokenInfo | null;
  error: AuthError | null;
}

// ============================================
// PKCE Types
// ============================================

export interface PKCEPair {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
}

export interface AuthorizationParams {
  state: string;
  nonce: string;
  codeVerifier: string;
  codeChallenge: string;
  redirectUri: string;
}

// ============================================
// Storage Types
// ============================================

export interface TokenStorage {
  get(key: string): string | null | Promise<string | null>;
  set(key: string, value: string): void | Promise<void>;
  remove(key: string): void | Promise<void>;
  clear(): void | Promise<void>;
}

export interface StorageKeys {
  accessToken: string;
  refreshToken: string;
  idToken: string;
  expiresAt: string;
  state: string;
  nonce: string;
  codeVerifier: string;
  returnTo: string;
}

// ============================================
// Event Types
// ============================================

export type AuthEvent =
  | { type: "INITIALIZED" }
  | { type: "LOGIN_STARTED" }
  | { type: "LOGIN_SUCCESS"; user: User; tokens: TokenInfo }
  | { type: "LOGIN_ERROR"; error: AuthError }
  | { type: "LOGOUT_STARTED" }
  | { type: "LOGOUT_SUCCESS" }
  | { type: "LOGOUT_ERROR"; error: AuthError }
  | { type: "TOKEN_REFRESHED"; tokens: TokenInfo }
  | { type: "TOKEN_REFRESH_ERROR"; error: AuthError }
  | { type: "SESSION_EXPIRED" };

export type AuthEventHandler = (event: AuthEvent) => void;

// ============================================
// Error Types
// ============================================

export class AuthError extends Error {
  constructor(
    public code: AuthErrorCode,
    message: string,
    public cause?: Error,
  ) {
    super(message);
    this.name = "AuthError";
  }
}

export type AuthErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "invalid_scope"
  | "access_denied"
  | "server_error"
  | "temporarily_unavailable"
  | "login_required"
  | "consent_required"
  | "interaction_required"
  | "invalid_token"
  | "insufficient_scope"
  | "token_expired"
  | "token_refresh_failed"
  | "pkce_error"
  | "state_mismatch"
  | "nonce_mismatch"
  | "network_error"
  | "configuration_error"
  | "unknown_error";

// ============================================
// Discovery Types
// ============================================

export interface OIDCDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  revocation_endpoint?: string;
  introspection_endpoint?: string;
  end_session_endpoint?: string;
  registration_endpoint?: string;
  scopes_supported: string[];
  response_types_supported: string[];
  response_modes_supported?: string[];
  grant_types_supported: string[];
  token_endpoint_auth_methods_supported?: string[];
  subject_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
  claims_supported?: string[];
  code_challenge_methods_supported?: string[];
}

// ============================================
// Callback Types
// ============================================

export interface CallbackParams {
  code?: string;
  state?: string;
  error?: string;
  error_description?: string;
}

export interface CallbackResult {
  success: boolean;
  user?: User;
  tokens?: TokenInfo;
  error?: AuthError;
  returnTo?: string;
}

// ============================================
// Login Options
// ============================================

export interface LoginOptions {
  /** URL to return to after login */
  returnTo?: string;
  /** Additional authorization parameters */
  authorizationParams?: Record<string, string>;
  /** Prompt parameter (none, login, consent, select_account) */
  prompt?: "none" | "login" | "consent" | "select_account";
  /** Login hint (email or identifier) */
  loginHint?: string;
  /** UI locales preference */
  uiLocales?: string;
  /** Maximum authentication age in seconds */
  maxAge?: number;
  /** ACR values requested */
  acrValues?: string;
}

export interface LogoutOptions {
  /** URL to return to after logout */
  returnTo?: string;
  /** Whether to federate logout (end session at IdP) @default true */
  federated?: boolean;
  /** Only clear local session, don't redirect @default false */
  localOnly?: boolean;
}
