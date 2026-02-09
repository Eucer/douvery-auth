/**
 * @douvery/auth/qwik - Qwik adapter
 */

import {
  createContextId,
  useContextProvider,
  useContext,
  useSignal,
  useTask$,
  useVisibleTask$,
  component$,
  Slot,
  type Signal,
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
} from "../index";

interface DouveryAuthContextValue {
  state: Signal<AuthState>;
  isInitialized: Signal<boolean>;
  isLoading: Signal<boolean>;
  error: Signal<Error | null>;
  client: DouveryAuthClient;
}

export const DouveryAuthContext =
  createContextId<DouveryAuthContextValue>("douvery-auth");

export interface DouveryAuthProviderProps {
  config: DouveryAuthConfig;
}

export const DouveryAuthProvider = component$<DouveryAuthProviderProps>(
  ({ config }) => {
    const client = createDouveryAuth(config);
    const state = useSignal<AuthState>(client.getState());
    const isInitialized = useSignal(false);
    const isLoading = useSignal(false);
    const error = useSignal<Error | null>(null);

    useContextProvider(DouveryAuthContext, {
      state,
      isInitialized,
      isLoading,
      error,
      client,
    });

    useVisibleTask$(() => {
      client
        .initialize()
        .then(() => {
          isInitialized.value = true;
          state.value = client.getState();
        })
        .catch((err) => {
          error.value = err instanceof Error ? err : new Error(String(err));
        });

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

export function useDouveryAuth() {
  return useContext(DouveryAuthContext);
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
  const { client, isLoading, error } = useDouveryAuth();

  const login = async (options?: LoginOptions) => {
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
  };

  const logout = async (options?: LogoutOptions) => {
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
  };

  const selectAccount = (options?: SelectAccountOptions) => {
    client.selectAccount(options);
  };

  const addAccount = (options?: AddAccountOptions) => {
    client.addAccount(options);
  };

  const register = (options?: RegisterOptions) => {
    client.register(options);
  };

  const recoverAccount = (options?: RecoverAccountOptions) => {
    client.recoverAccount(options);
  };

  const verifyAccount = (options?: VerifyAccountOptions) => {
    client.verifyAccount(options);
  };

  const upgradeAccount = (options?: UpgradeAccountOptions) => {
    client.upgradeAccount(options);
  };

  const setupPasskey = (options?: SetupPasskeyOptions) => {
    client.setupPasskey(options);
  };

  const setupAddress = (options?: SetupAddressOptions) => {
    client.setupAddress(options);
  };

  const revokeToken = async (options?: RevokeTokenOptions) => {
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
  };

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
  const { client } = useDouveryAuth();
  return {
    loginUrl: (options?: LoginOptions): AuthUrl =>
      client.buildLoginUrl(options),
    logoutUrl: (options?: LogoutOptions): AuthUrl =>
      client.buildLogoutUrl(options),
    selectAccountUrl: (options?: SelectAccountOptions): AuthUrl =>
      client.buildSelectAccountUrl(options),
    addAccountUrl: (options?: AddAccountOptions): AuthUrl =>
      client.buildAddAccountUrl(options),
    registerUrl: (options?: RegisterOptions): AuthUrl =>
      client.buildRegisterUrl(options),
    recoverAccountUrl: (options?: RecoverAccountOptions): AuthUrl =>
      client.buildRecoverAccountUrl(options),
    verifyAccountUrl: (options?: VerifyAccountOptions): AuthUrl =>
      client.buildVerifyAccountUrl(options),
    upgradeAccountUrl: (options?: UpgradeAccountOptions): AuthUrl =>
      client.buildUpgradeAccountUrl(options),
    setupPasskeyUrl: (options?: SetupPasskeyOptions): AuthUrl =>
      client.buildSetupPasskeyUrl(options),
    setupAddressUrl: (options?: SetupAddressOptions): AuthUrl =>
      client.buildSetupAddressUrl(options),
  };
}

/** Get session status helpers */
export function useSessionStatus() {
  const { client, state } = useDouveryAuth();
  const isExpired = useSignal(client.isSessionExpired());
  const needsVerification = useSignal(client.needsEmailVerification());
  const isGuest = useSignal(client.isGuestAccount());

  useTask$(({ track }) => {
    track(() => state.value);
    isExpired.value = client.isSessionExpired();
    needsVerification.value = client.needsEmailVerification();
    isGuest.value = client.isGuestAccount();
  });

  return { isExpired, needsVerification, isGuest };
}

export { DouveryAuthClient, createDouveryAuth } from "../index";
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
} from "../index";
