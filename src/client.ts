/**
 * @douvery/auth - Auth Client
 * Main OAuth 2.0/OIDC client implementation
 */

import type {
  DouveryAuthConfig,
  TokenSet,
  TokenInfo,
  User,
  AuthState,
  AuthEvent,
  AuthEventHandler,
  OIDCDiscovery,
  CallbackResult,
  LoginOptions,
  LogoutOptions,
  DecodedIdToken,
  SelectAccountOptions,
  RegisterOptions,
  RecoverAccountOptions,
  VerifyAccountOptions,
  UpgradeAccountOptions,
  SetupPasskeyOptions,
  SetupAddressOptions,
  AddAccountOptions,
  RevokeTokenOptions,
  AuthNavigationOptions,
  AuthUrl,
} from "./types";
import { AuthError } from "./types";
import {
  generatePKCEPair,
  generateState,
  generateNonce,
  decodeJWT,
  isTokenExpired,
} from "./pkce";
import { createStorage, TokenManager } from "./storage";

const DEFAULT_ISSUER = "https://auth.douvery.com";
const DEFAULT_SCOPES = ["openid", "profile", "email"];

export class DouveryAuthClient {
  private config: Required<
    Pick<DouveryAuthConfig, "clientId" | "issuer" | "redirectUri" | "scopes">
  > &
    DouveryAuthConfig;
  private tokenManager: TokenManager;
  private discovery: OIDCDiscovery | null = null;
  private eventHandlers: Set<AuthEventHandler> = new Set();
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private state: AuthState = {
    status: "loading",
    user: null,
    tokens: null,
    error: null,
  };

  constructor(config: DouveryAuthConfig) {
    this.config = {
      issuer: DEFAULT_ISSUER,
      scopes: DEFAULT_SCOPES,
      storage: "localStorage",
      autoRefresh: true,
      refreshThreshold: 60,
      debug: false,
      ...config,
    };

    const storage =
      config.customStorage ??
      createStorage(this.config.storage ?? "localStorage");
    this.tokenManager = new TokenManager(storage);
  }

  /** Initialize the auth client */
  async initialize(): Promise<AuthState> {
    this.log("Initializing auth client...");

    try {
      if (this.isCallback()) {
        this.log("Handling OAuth callback...");
        const result = await this.handleCallback();
        if (result.success && result.user && result.tokens) {
          this.updateState({
            status: "authenticated",
            user: result.user,
            tokens: result.tokens,
            error: null,
          });
          this.setupAutoRefresh();
        } else {
          this.updateState({
            status: "unauthenticated",
            user: null,
            tokens: null,
            error: result.error ?? null,
          });
        }
      } else {
        const tokens = await this.tokenManager.getTokens();
        if (tokens && tokens.accessToken) {
          if (!isTokenExpired(tokens.accessToken)) {
            this.log("Found valid existing session");
            const user = await this.fetchUser(tokens.accessToken);
            this.updateState({
              status: "authenticated",
              user,
              tokens,
              error: null,
            });
            this.setupAutoRefresh();
          } else if (tokens.refreshToken) {
            this.log("Access token expired, attempting refresh...");
            await this.refreshTokens();
          } else {
            this.log("Session expired, no refresh token");
            await this.tokenManager.clearTokens();
            this.updateState({
              status: "unauthenticated",
              user: null,
              tokens: null,
              error: null,
            });
          }
        } else {
          this.log("No existing session found");
          this.updateState({
            status: "unauthenticated",
            user: null,
            tokens: null,
            error: null,
          });
        }
      }

      this.emit({ type: "INITIALIZED" });
    } catch (error) {
      this.log("Initialization error:", error);
      this.updateState({
        status: "unauthenticated",
        user: null,
        tokens: null,
        error:
          error instanceof AuthError
            ? error
            : new AuthError(
                "unknown_error",
                "Initialization failed",
                error as Error,
              ),
      });
    }

    return this.state;
  }

  /** Start the login flow */
  async login(options: LoginOptions = {}): Promise<void> {
    this.log("Starting login flow...");
    this.emit({ type: "LOGIN_STARTED" });

    try {
      const discovery = await this.getDiscovery();
      const pkce = await generatePKCEPair();
      const state = generateState();
      const nonce = generateNonce();

      await this.tokenManager.saveState(state);
      await this.tokenManager.saveNonce(nonce);
      await this.tokenManager.saveCodeVerifier(pkce.codeVerifier);

      if (options.returnTo) {
        await this.tokenManager.saveReturnTo(options.returnTo);
      }

      const params = new URLSearchParams({
        response_type: "code",
        client_id: this.config.clientId,
        redirect_uri: this.config.redirectUri,
        scope: this.config.scopes!.join(" "),
        state,
        nonce,
        code_challenge: pkce.codeChallenge,
        code_challenge_method: pkce.codeChallengeMethod,
        ...options.authorizationParams,
      });

      if (options.prompt) params.set("prompt", options.prompt);
      if (options.loginHint) params.set("login_hint", options.loginHint);
      if (options.uiLocales) params.set("ui_locales", options.uiLocales);
      if (options.maxAge !== undefined)
        params.set("max_age", options.maxAge.toString());
      if (options.acrValues) params.set("acr_values", options.acrValues);

      const authUrl = `${discovery.authorization_endpoint}?${params}`;
      this.log("Redirecting to:", authUrl);

      window.location.href = authUrl;
    } catch (error) {
      const authError =
        error instanceof AuthError
          ? error
          : new AuthError(
              "configuration_error",
              "Login failed",
              error as Error,
            );
      this.emit({ type: "LOGIN_ERROR", error: authError });
      throw authError;
    }
  }

  /** Logout the user */
  async logout(options: LogoutOptions = {}): Promise<void> {
    this.log("Starting logout...");
    this.emit({ type: "LOGOUT_STARTED" });

    try {
      await this.tokenManager.clearAll();
      this.clearAutoRefresh();

      this.updateState({
        status: "unauthenticated",
        user: null,
        tokens: null,
        error: null,
      });

      if (options.localOnly) {
        this.emit({ type: "LOGOUT_SUCCESS" });
        return;
      }

      if (options.federated !== false) {
        const discovery = await this.getDiscovery();
        if (discovery.end_session_endpoint) {
          const params = new URLSearchParams();
          if (this.state.tokens?.idToken) {
            params.set("id_token_hint", this.state.tokens.idToken);
          }
          if (options.returnTo || this.config.postLogoutRedirectUri) {
            params.set(
              "post_logout_redirect_uri",
              options.returnTo || this.config.postLogoutRedirectUri!,
            );
          }
          params.set("client_id", this.config.clientId);

          const logoutUrl = `${discovery.end_session_endpoint}?${params}`;
          this.log("Redirecting to logout:", logoutUrl);
          window.location.href = logoutUrl;
          return;
        }
      }

      this.emit({ type: "LOGOUT_SUCCESS" });

      if (options.returnTo) {
        window.location.href = options.returnTo;
      }
    } catch (error) {
      const authError =
        error instanceof AuthError
          ? error
          : new AuthError("unknown_error", "Logout failed", error as Error);
      this.emit({ type: "LOGOUT_ERROR", error: authError });
      throw authError;
    }
  }

  /** Check if current URL is an OAuth callback */
  isCallback(): boolean {
    if (typeof window === "undefined") return false;
    const params = new URLSearchParams(window.location.search);
    return params.has("code") || params.has("error");
  }

  /** Handle the OAuth callback */
  async handleCallback(): Promise<CallbackResult> {
    this.log("Processing callback...");

    if (typeof window === "undefined") {
      return {
        success: false,
        error: new AuthError(
          "configuration_error",
          "Cannot handle callback on server",
        ),
      };
    }

    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const stateParam = params.get("state");
    const errorParam = params.get("error");
    const errorDescription = params.get("error_description");

    if (errorParam) {
      const error = new AuthError(
        errorParam as any,
        errorDescription ?? "Authorization failed",
      );
      return { success: false, error };
    }

    const savedState = await this.tokenManager.getState();
    if (!stateParam || stateParam !== savedState) {
      return {
        success: false,
        error: new AuthError("state_mismatch", "State parameter mismatch"),
      };
    }

    if (!code) {
      return {
        success: false,
        error: new AuthError(
          "invalid_request",
          "No authorization code received",
        ),
      };
    }

    const codeVerifier = await this.tokenManager.getCodeVerifier();
    if (!codeVerifier) {
      return {
        success: false,
        error: new AuthError("pkce_error", "No code verifier found"),
      };
    }

    try {
      const tokens = await this.exchangeCode(code, codeVerifier);
      await this.tokenManager.setTokens(tokens);
      const user = await this.fetchUser(tokens.accessToken);
      const returnTo = await this.tokenManager.getReturnTo();

      await this.tokenManager.clearState();
      await this.tokenManager.clearNonce();
      await this.tokenManager.clearCodeVerifier();
      await this.tokenManager.clearReturnTo();

      window.history.replaceState({}, "", window.location.pathname);

      this.emit({ type: "LOGIN_SUCCESS", user, tokens });

      return { success: true, user, tokens, returnTo: returnTo ?? undefined };
    } catch (error) {
      const authError =
        error instanceof AuthError
          ? error
          : new AuthError(
              "invalid_grant",
              "Token exchange failed",
              error as Error,
            );
      this.emit({ type: "LOGIN_ERROR", error: authError });
      return { success: false, error: authError };
    }
  }

  private async exchangeCode(
    code: string,
    codeVerifier: string,
  ): Promise<TokenInfo> {
    const discovery = await this.getDiscovery();

    const response = await fetch(discovery.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: this.config.redirectUri,
        client_id: this.config.clientId,
        code_verifier: codeVerifier,
      }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new AuthError(
        error.error ?? "invalid_grant",
        error.error_description ?? "Token exchange failed",
      );
    }

    const tokenSet: TokenSet = await response.json();
    return this.tokenSetToInfo(tokenSet);
  }

  /** Refresh the access token */
  async refreshTokens(): Promise<TokenInfo> {
    this.log("Refreshing tokens...");

    const tokens = await this.tokenManager.getTokens();
    if (!tokens?.refreshToken) {
      throw new AuthError("token_refresh_failed", "No refresh token available");
    }

    const discovery = await this.getDiscovery();

    const response = await fetch(discovery.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: tokens.refreshToken,
        client_id: this.config.clientId,
      }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      const authError = new AuthError(
        error.error ?? "token_refresh_failed",
        error.error_description ?? "Token refresh failed",
      );
      this.emit({ type: "TOKEN_REFRESH_ERROR", error: authError });
      await this.tokenManager.clearTokens();
      this.updateState({
        status: "unauthenticated",
        user: null,
        tokens: null,
        error: authError,
      });
      this.emit({ type: "SESSION_EXPIRED" });
      throw authError;
    }

    const tokenSet: TokenSet = await response.json();
    const newTokens = this.tokenSetToInfo(tokenSet);
    await this.tokenManager.setTokens(newTokens);

    const user = newTokens.idToken
      ? this.extractUserFromIdToken(newTokens.idToken)
      : this.state.user;

    this.updateState({ ...this.state, tokens: newTokens, user });
    this.emit({ type: "TOKEN_REFRESHED", tokens: newTokens });
    this.setupAutoRefresh();

    return newTokens;
  }

  /** Get current access token (auto-refreshes if needed) */
  async getAccessToken(): Promise<string | null> {
    const tokens = await this.tokenManager.getTokens();
    if (!tokens) return null;

    if (isTokenExpired(tokens.accessToken)) {
      if (tokens.refreshToken) {
        const newTokens = await this.refreshTokens();
        return newTokens.accessToken;
      }
      return null;
    }

    return tokens.accessToken;
  }

  // ============================================
  // Navigation Methods
  // ============================================

  /** Redirect to select/switch account */
  selectAccount(options: SelectAccountOptions = {}): void {
    const url = this.buildSelectAccountUrl(options);
    this.navigate(url, options);
  }

  /** Build select-account URL without redirecting */
  buildSelectAccountUrl(options: SelectAccountOptions = {}): AuthUrl {
    const params = new URLSearchParams();
    if (options.returnTo) params.set("continue", options.returnTo);
    if (options.clientId) params.set("client_id", options.clientId);
    if (options.loginHint) params.set("login_hint", options.loginHint);
    return this.createAuthUrl("/select-account", params);
  }

  /** Redirect to add another account (multi-session) */
  addAccount(options: AddAccountOptions = {}): void {
    const url = this.buildAddAccountUrl(options);
    this.navigate(url, options);
  }

  /** Build add-account URL without redirecting */
  buildAddAccountUrl(options: AddAccountOptions = {}): AuthUrl {
    const params = new URLSearchParams({ add_account: "true" });
    if (options.returnTo) params.set("continue", options.returnTo);
    if (options.clientId) params.set("client_id", options.clientId);
    if (options.loginHint) params.set("login_hint", options.loginHint);
    return this.createAuthUrl("/login", params);
  }

  /** Redirect to register a new account */
  register(options: RegisterOptions = {}): void {
    const url = this.buildRegisterUrl(options);
    this.navigate(url, options);
  }

  /** Build register URL without redirecting */
  buildRegisterUrl(options: RegisterOptions = {}): AuthUrl {
    const params = new URLSearchParams();
    if (options.returnTo) params.set("continue", options.returnTo);
    if (options.clientId) params.set("client_id", options.clientId);
    if (options.email) params.set("email", options.email);
    if (options.firstName) params.set("first_name", options.firstName);
    if (options.lastName) params.set("last_name", options.lastName);
    if (options.uiLocales) params.set("ui_locales", options.uiLocales);
    return this.createAuthUrl("/register", params);
  }

  /** Redirect to recover account (forgot password) */
  recoverAccount(options: RecoverAccountOptions = {}): void {
    const url = this.buildRecoverAccountUrl(options);
    this.navigate(url, options);
  }

  /** Build recover-account URL without redirecting */
  buildRecoverAccountUrl(options: RecoverAccountOptions = {}): AuthUrl {
    const params = new URLSearchParams();
    if (options.returnTo) params.set("continue", options.returnTo);
    if (options.clientId) params.set("client_id", options.clientId);
    if (options.email) params.set("email", options.email);
    return this.createAuthUrl("/recover-account", params);
  }

  /** Redirect to verify account (email verification) */
  verifyAccount(options: VerifyAccountOptions = {}): void {
    const url = this.buildVerifyAccountUrl(options);
    this.navigate(url, options);
  }

  /** Build verify-account URL without redirecting */
  buildVerifyAccountUrl(options: VerifyAccountOptions = {}): AuthUrl {
    const params = new URLSearchParams();
    if (options.returnTo) params.set("continue", options.returnTo);
    if (options.clientId) params.set("client_id", options.clientId);
    if (options.email) params.set("email", options.email);
    return this.createAuthUrl("/verify-account", params);
  }

  /** Redirect to upgrade account (guest → full account) */
  upgradeAccount(options: UpgradeAccountOptions = {}): void {
    const url = this.buildUpgradeAccountUrl(options);
    this.navigate(url, options);
  }

  /** Build upgrade-account URL without redirecting */
  buildUpgradeAccountUrl(options: UpgradeAccountOptions = {}): AuthUrl {
    const params = new URLSearchParams();
    if (options.returnTo) params.set("continue", options.returnTo);
    if (options.clientId) params.set("client_id", options.clientId);
    if (options.scopes?.length) params.set("scope", options.scopes.join(" "));
    return this.createAuthUrl("/upgrade-account", params);
  }

  /** Redirect to passkey setup */
  setupPasskey(options: SetupPasskeyOptions = {}): void {
    const url = this.buildSetupPasskeyUrl(options);
    this.navigate(url, options);
  }

  /** Build setup-passkey URL without redirecting */
  buildSetupPasskeyUrl(options: SetupPasskeyOptions = {}): AuthUrl {
    const params = new URLSearchParams();
    if (options.returnTo) params.set("continue", options.returnTo);
    if (options.clientId) params.set("client_id", options.clientId);
    return this.createAuthUrl("/setup-passkey", params);
  }

  /** Redirect to address setup */
  setupAddress(options: SetupAddressOptions = {}): void {
    const url = this.buildSetupAddressUrl(options);
    this.navigate(url, options);
  }

  /** Build setup-address URL without redirecting */
  buildSetupAddressUrl(options: SetupAddressOptions = {}): AuthUrl {
    const params = new URLSearchParams();
    if (options.returnTo) params.set("continue", options.returnTo);
    if (options.clientId) params.set("client_id", options.clientId);
    return this.createAuthUrl("/setup-address", params);
  }

  /** Build a login URL without redirecting (useful for links/buttons) */
  buildLoginUrl(options: LoginOptions = {}): AuthUrl {
    const params = new URLSearchParams();
    if (options.returnTo) params.set("continue", options.returnTo);
    if (options.loginHint) params.set("email", options.loginHint);
    if (options.prompt) params.set("prompt", options.prompt);
    if (options.uiLocales) params.set("ui_locales", options.uiLocales);
    return this.createAuthUrl("/login", params);
  }

  /** Build a logout URL without redirecting */
  buildLogoutUrl(options: LogoutOptions = {}): AuthUrl {
    const params = new URLSearchParams();
    if (options.returnTo) params.set("continue", options.returnTo);
    return this.createAuthUrl("/logout", params);
  }

  /** Revoke a token (access or refresh) */
  async revokeToken(options: RevokeTokenOptions = {}): Promise<void> {
    this.log("Revoking token...");

    const token =
      options.token ?? (await this.tokenManager.getTokens())?.accessToken;
    if (!token) {
      throw new AuthError("invalid_token", "No token to revoke");
    }

    const revokeUrl = `${this.config.issuer}/oauth/revoke`;

    const body = new URLSearchParams({
      token,
      client_id: this.config.clientId,
    });
    if (options.tokenTypeHint) {
      body.set("token_type_hint", options.tokenTypeHint);
    }

    const response = await fetch(revokeUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new AuthError(
        error.error ?? "server_error",
        error.error_description ?? "Token revocation failed",
      );
    }

    this.log("Token revoked successfully");
  }

  /** Check if the user's session is expired */
  isSessionExpired(): boolean {
    if (!this.state.tokens) return true;
    return isTokenExpired(this.state.tokens.accessToken);
  }

  /** Check if user needs email verification */
  needsEmailVerification(): boolean {
    return this.state.user?.emailVerified === false;
  }

  /** Check if user is a guest account */
  isGuestAccount(): boolean {
    return (
      (this.state.user as Record<string, unknown>)?.accountType === "guest"
    );
  }

  private tokenSetToInfo(tokenSet: TokenSet): TokenInfo {
    return {
      accessToken: tokenSet.access_token,
      refreshToken: tokenSet.refresh_token,
      idToken: tokenSet.id_token,
      expiresAt: Date.now() + tokenSet.expires_in * 1000,
      tokenType: tokenSet.token_type,
      scope: tokenSet.scope?.split(" ") ?? [],
    };
  }

  /** Build an AuthUrl object for a given path and params */
  private createAuthUrl(path: string, params: URLSearchParams): AuthUrl {
    const query = params.toString();
    const url = `${this.config.issuer}${path}${query ? `?${query}` : ""}`;
    return {
      url,
      redirect: () => {
        window.location.href = url;
      },
      open: () => {
        return window.open(url, "_blank");
      },
    };
  }

  /** Navigate to an auth URL, respecting openInNewTab option */
  private navigate(authUrl: AuthUrl, options: AuthNavigationOptions): void {
    if (options.openInNewTab) {
      authUrl.open();
    } else {
      authUrl.redirect();
    }
  }

  private async fetchUser(accessToken: string): Promise<User> {
    const discovery = await this.getDiscovery();

    const response = await fetch(discovery.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) {
      throw new AuthError("invalid_token", "Failed to fetch user info");
    }

    const userInfo = await response.json();
    return this.normalizeUser(userInfo);
  }

  private extractUserFromIdToken(idToken: string): User {
    const claims = decodeJWT<DecodedIdToken>(idToken);
    return this.normalizeUser(claims);
  }

  private normalizeUser(claims: Record<string, unknown>): User {
    return {
      id: claims.sub as string,
      email: claims.email as string | undefined,
      emailVerified: claims.email_verified as boolean | undefined,
      name: claims.name as string | undefined,
      firstName: claims.given_name as string | undefined,
      lastName: claims.family_name as string | undefined,
      picture: claims.picture as string | undefined,
      phoneNumber: claims.phone_number as string | undefined,
      phoneNumberVerified: claims.phone_number_verified as boolean | undefined,
      locale: claims.locale as string | undefined,
      ...claims,
    };
  }

  private async getDiscovery(): Promise<OIDCDiscovery> {
    if (this.discovery) return this.discovery;
    const discoveryUrl = `${this.config.issuer}/.well-known/openid-configuration`;
    const response = await fetch(discoveryUrl);
    if (!response.ok) {
      throw new AuthError(
        "configuration_error",
        "Failed to fetch discovery document",
      );
    }
    this.discovery = await response.json();
    return this.discovery!;
  }

  private setupAutoRefresh(): void {
    if (!this.config.autoRefresh || !this.state.tokens) return;
    this.clearAutoRefresh();
    const expiresIn = this.state.tokens.expiresAt - Date.now();
    const refreshIn = expiresIn - this.config.refreshThreshold! * 1000;
    if (refreshIn > 0) {
      this.log(`Scheduling token refresh in ${Math.round(refreshIn / 1000)}s`);
      this.refreshTimer = setTimeout(() => {
        this.refreshTokens().catch((error) =>
          this.log("Auto-refresh failed:", error),
        );
      }, refreshIn);
    }
  }

  private clearAutoRefresh(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  getState(): AuthState {
    return { ...this.state };
  }

  isAuthenticated(): boolean {
    return this.state.status === "authenticated";
  }

  getUser(): User | null {
    return this.state.user;
  }

  subscribe(handler: AuthEventHandler): () => void {
    this.eventHandlers.add(handler);
    return () => this.eventHandlers.delete(handler);
  }

  private updateState(newState: AuthState): void {
    this.state = newState;
  }

  private emit(event: AuthEvent): void {
    this.eventHandlers.forEach((handler) => {
      try {
        handler(event);
      } catch (error) {
        console.error("Event handler error:", error);
      }
    });
  }

  private log(...args: unknown[]): void {
    if (this.config.debug) {
      console.log("[DouveryAuth]", ...args);
    }
  }
}

/** Create a new DouveryAuthClient instance */
export function createDouveryAuth(
  config: DouveryAuthConfig,
): DouveryAuthClient {
  return new DouveryAuthClient(config);
}
