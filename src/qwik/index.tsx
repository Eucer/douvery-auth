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

  return { login, logout, isLoading };
}

export { DouveryAuthClient, createDouveryAuth } from "../index";
export type {
  DouveryAuthConfig,
  AuthState,
  User,
  LoginOptions,
  LogoutOptions,
} from "../index";
