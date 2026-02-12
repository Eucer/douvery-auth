/**
 * @douvery/auth/qwik - Qwik adapter
 *
 * Uses QRL for config to avoid Qwik serialization issues with
 * function-based storage adapters (customStorage).
 * The client is created inside useVisibleTask$ and wrapped with
 * noSerialize() since DouveryAuthClient has non-serializable methods.
 */

import {
  createContextId,
  useContextProvider,
  useContext,
  useSignal,
  useTask$,
  useVisibleTask$,
  component$,
  $,
  Slot,
  noSerialize,
  type Signal,
  type NoSerialize,
  type QRL,
} from "@builder.io/qwik";
import {
  DouveryAuthClient,
  createDouveryAuth,
  type DouveryAuthConfig,
  type AuthState,
  type User,
  type LoginOptions,
  type LogoutOptions,
  type SelectAccountOptions,
  type RegisterOptions,
  type RecoverAccountOptions,
  type VerifyAccountOptions,
  type UpgradeAccountOptions,
  type SetupPasskeyOptions,
  type SetupAddressOptions,
  type AddAccountOptions,
  type RevokeTokenOptions,
  type AuthUrl,
} from "@douvery/auth";

// ============================================================================
// Context
// ============================================================================

interface DouveryAuthContextValue {
  state: Signal<AuthState>;
  isInitialized: Signal<boolean>;
  isLoading: Signal<boolean>;
  error: Signal<Error | null>;
  clientRef: Signal<NoSerialize<DouveryAuthClient> | undefined>;
  /** Application-specific user data from SSR (e.g. routeLoader$). */
  appUser: Signal<unknown>;
  appUserAuthenticated: Signal<boolean>;
}

export const DouveryAuthContext =
  createContextId<DouveryAuthContextValue>("douvery-auth");

// ============================================================================
// Provider
// ============================================================================

export interface DouveryAuthProviderProps {
  /**
   * QRL that returns the auth configuration.
   * Use $(() => getDouveryAuthConfig()) to wrap your config factory.
   * This avoids Qwik serialization issues with customStorage functions.
   */
  config$: QRL<() => DouveryAuthConfig>;
  /**
   * Optional application-specific user data loaded from SSR (routeLoader$).
   * This is separate from OAuth user – it holds the full app user object
   * (e.g. UserACC with address, active, sessionId, etc.).
   * Pass the routeLoader$ signal directly.
   */
  appUser?: Signal<unknown>;
}

const DEFAULT_STATE: AuthState = {
  status: "unauthenticated",
  user: null,
  tokens: null,
  error: null,
};

export const DouveryAuthProvider = component$<DouveryAuthProviderProps>(
  ({ config$, appUser: externalAppUser }) => {
    // All signals are serializable - no functions stored directly
    const state = useSignal<AuthState>(DEFAULT_STATE);
    const isInitialized = useSignal(false);
    const isLoading = useSignal(false);
    const error = useSignal<Error | null>(null);
    const clientRef = useSignal<NoSerialize<DouveryAuthClient>>();

    // App user data: use external signal if provided, otherwise create internal one
    const internalAppUser = useSignal<unknown>(externalAppUser?.value ?? null);
    const appUser = externalAppUser ?? internalAppUser;
    const appUserAuthenticated = useSignal<boolean>(!!appUser.value);

    // Keep appUserAuthenticated in sync
    useTask$(({ track }) => {
      const u = track(() => appUser.value);
      appUserAuthenticated.value = !!u;
    });

    useContextProvider(DouveryAuthContext, {
      state,
      isInitialized,
      isLoading,
      error,
      clientRef,
      appUser,
      appUserAuthenticated,
    });

    // Client creation deferred to browser-only task.
    // The QRL is invoked here, returning the full config (with customStorage).
    // noSerialize() wraps the client so Qwik doesn't try to serialize it.
    useVisibleTask$(async () => {
      let config: DouveryAuthConfig | undefined;
      try {
        config = await config$();
      } catch (err) {
        error.value = err instanceof Error ? err : new Error(String(err));
        return;
      }

      if (!config) {
        error.value = new Error(
          "[DouveryAuthProvider] config$() returned undefined. " +
            "Check that the QRL correctly returns a DouveryAuthConfig object.",
        );
        return;
      }

      const client = createDouveryAuth(config);
      clientRef.value = noSerialize(client);

      try {
        await client.initialize();
        isInitialized.value = true;
        state.value = client.getState();
      } catch (err) {
        error.value = err instanceof Error ? err : new Error(String(err));
      }

      const unsubscribe = client.subscribe((event) => {
        state.value = client.getState();
        if (
          event.type === "LOGIN_ERROR" ||
          event.type === "LOGOUT_ERROR" ||
          event.type === "TOKEN_REFRESH_ERROR"
        ) {
          error.value = event.error;
        }
      });

      return () => unsubscribe();
    });

    return <Slot />;
  },
);

// ============================================================================
// Hooks
// ============================================================================

export function useDouveryAuth() {
  return useContext(DouveryAuthContext);
}

/**
 * Internal helper: safely access the client from context.
 * Throws if the client hasn't been initialized yet (before useVisibleTask$ runs).
 */
function getClient(ctx: DouveryAuthContextValue): DouveryAuthClient {
  const client = ctx.clientRef.value;
  if (!client) {
    throw new Error(
      "DouveryAuth client not initialized. " +
        "Ensure DouveryAuthProvider is mounted and the page has hydrated.",
    );
  }
  return client;
}

export function useUser(): Signal<User | null> {
  const { state } = useDouveryAuth();
  const user = useSignal<User | null>(state.value.user);
  useTask$(({ track }) => {
    track(() => state.value);
    user.value = state.value.user;
  });
  return user;
}

export function useIsAuthenticated(): Signal<boolean> {
  const { state } = useDouveryAuth();
  const isAuth = useSignal(state.value.status === "authenticated");
  useTask$(({ track }) => {
    track(() => state.value);
    isAuth.value = state.value.status === "authenticated";
  });
  return isAuth;
}

export function useAuthActions() {
  const ctx = useDouveryAuth();
  const { isLoading, error } = ctx;

  const login = $(async (options?: LoginOptions) => {
    const client = getClient(ctx);
    isLoading.value = true;
    error.value = null;
    try {
      await client.login(options);
    } catch (err) {
      error.value = err instanceof Error ? err : new Error(String(err));
      throw err;
    } finally {
      isLoading.value = false;
    }
  });

  const logout = $(async (options?: LogoutOptions) => {
    const client = getClient(ctx);
    isLoading.value = true;
    error.value = null;
    try {
      await client.logout(options);
    } catch (err) {
      error.value = err instanceof Error ? err : new Error(String(err));
      throw err;
    } finally {
      isLoading.value = false;
    }
  });

  const selectAccount = $((options?: SelectAccountOptions) => {
    getClient(ctx).selectAccount(options);
  });

  const addAccount = $((options?: AddAccountOptions) => {
    getClient(ctx).addAccount(options);
  });

  const register = $((options?: RegisterOptions) => {
    getClient(ctx).register(options);
  });

  const recoverAccount = $((options?: RecoverAccountOptions) => {
    getClient(ctx).recoverAccount(options);
  });

  const verifyAccount = $((options?: VerifyAccountOptions) => {
    getClient(ctx).verifyAccount(options);
  });

  const upgradeAccount = $((options?: UpgradeAccountOptions) => {
    getClient(ctx).upgradeAccount(options);
  });

  const setupPasskey = $((options?: SetupPasskeyOptions) => {
    getClient(ctx).setupPasskey(options);
  });

  const setupAddress = $((options?: SetupAddressOptions) => {
    getClient(ctx).setupAddress(options);
  });

  const revokeToken = $(async (options?: RevokeTokenOptions) => {
    const client = getClient(ctx);
    isLoading.value = true;
    error.value = null;
    try {
      await client.revokeToken(options);
    } catch (err) {
      error.value = err instanceof Error ? err : new Error(String(err));
      throw err;
    } finally {
      isLoading.value = false;
    }
  });

  return {
    login,
    logout,
    selectAccount,
    addAccount,
    register,
    recoverAccount,
    verifyAccount,
    upgradeAccount,
    setupPasskey,
    setupAddress,
    revokeToken,
    isLoading,
  };
}

/** Get URL builders for auth pages (non-redirecting, useful for <a> tags) */
export function useAuthUrls() {
  const ctx = useDouveryAuth();
  return {
    loginUrl: $(
      (options?: LoginOptions): AuthUrl =>
        getClient(ctx).buildLoginUrl(options),
    ),
    logoutUrl: $(
      (options?: LogoutOptions): AuthUrl =>
        getClient(ctx).buildLogoutUrl(options),
    ),
    selectAccountUrl: $(
      (options?: SelectAccountOptions): AuthUrl =>
        getClient(ctx).buildSelectAccountUrl(options),
    ),
    addAccountUrl: $(
      (options?: AddAccountOptions): AuthUrl =>
        getClient(ctx).buildAddAccountUrl(options),
    ),
    registerUrl: $(
      (options?: RegisterOptions): AuthUrl =>
        getClient(ctx).buildRegisterUrl(options),
    ),
    recoverAccountUrl: $(
      (options?: RecoverAccountOptions): AuthUrl =>
        getClient(ctx).buildRecoverAccountUrl(options),
    ),
    verifyAccountUrl: $(
      (options?: VerifyAccountOptions): AuthUrl =>
        getClient(ctx).buildVerifyAccountUrl(options),
    ),
    upgradeAccountUrl: $(
      (options?: UpgradeAccountOptions): AuthUrl =>
        getClient(ctx).buildUpgradeAccountUrl(options),
    ),
    setupPasskeyUrl: $(
      (options?: SetupPasskeyOptions): AuthUrl =>
        getClient(ctx).buildSetupPasskeyUrl(options),
    ),
    setupAddressUrl: $(
      (options?: SetupAddressOptions): AuthUrl =>
        getClient(ctx).buildSetupAddressUrl(options),
    ),
  };
}

/** Get session status helpers */
export function useSessionStatus() {
  const ctx = useDouveryAuth();
  const { state } = ctx;
  const c = ctx.clientRef.value;
  const isExpired = useSignal(c ? c.isSessionExpired() : false);
  const needsVerification = useSignal(c ? c.needsEmailVerification() : false);
  const isGuest = useSignal(c ? c.isGuestAccount() : false);

  useTask$(({ track }) => {
    track(() => state.value);
    const client = ctx.clientRef.value;
    if (client) {
      isExpired.value = client.isSessionExpired();
      needsVerification.value = client.needsEmailVerification();
      isGuest.value = client.isGuestAccount();
    }
  });

  return { isExpired, needsVerification, isGuest };
}

// ============================================================================
// App User hooks
// ============================================================================

/**
 * Returns the application-specific user data provided via `appUser` prop.
 * Cast to your app's user type: `const user = useAppUser<UserACC>()`.
 * Returns `{ user: Signal<T | null>, isAuthenticated: Signal<boolean> }`.
 */
export function useAppUser<T = unknown>() {
  const { appUser, appUserAuthenticated } = useDouveryAuth();
  return {
    user: appUser as Signal<T | null>,
    isAuthenticated: appUserAuthenticated,
  };
}

/**
 * Full app user context with refresh capabilities.
 * Use when you need to re-fetch user data from the server.
 */
export function useAppUserActions<T = unknown>() {
  const { appUser, appUserAuthenticated } = useDouveryAuth();

  const updateUser = $((userData: T | null) => {
    (appUser as Signal<T | null>).value = userData;
    appUserAuthenticated.value = !!userData;
  });

  const refreshUser = $(async () => {
    try {
      const response = await fetch("/api/auth/me", {
        method: "GET",
        credentials: "include",
        headers: { "Cache-Control": "no-cache", Pragma: "no-cache" },
      });

      if (response.ok) {
        const data = await response.json();
        (appUser as Signal<T | null>).value = data.user;
        appUserAuthenticated.value = true;
      } else if (response.status === 401 || response.status === 403) {
        (appUser as Signal<T | null>).value = null;
        appUserAuthenticated.value = false;
      }
    } catch {
      // Network error: keep current state
    }
  });

  return {
    user: appUser as Signal<T | null>,
    isAuthenticated: appUserAuthenticated,
    updateUser,
    refreshUser,
  };
}

// ============================================================================
// Re-exports
// ============================================================================

export { DouveryAuthClient, createDouveryAuth } from "@douvery/auth";
export type {
  DouveryAuthConfig,
  AuthState,
  User,
  LoginOptions,
  LogoutOptions,
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
  CookieAdapter,
  CookieSetOptions,
} from "@douvery/auth";

// Session adapter for Qwik City
export { createQwikSessionAdapter } from "./session";
