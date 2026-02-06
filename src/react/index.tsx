/**
 * @douvery/auth/react - React adapter
 */

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useMemo,
  type ReactNode,
} from "react";
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
  state: AuthState;
  isInitialized: boolean;
  isLoading: boolean;
  user: User | null;
  isAuthenticated: boolean;
  accessToken: string | null;
  error: Error | null;
  login: (options?: LoginOptions) => Promise<void>;
  logout: (options?: LogoutOptions) => Promise<void>;
  getAccessToken: () => Promise<string | null>;
  refreshTokens: () => Promise<void>;
  client: DouveryAuthClient;
}

const DouveryAuthContext = createContext<DouveryAuthContextValue | null>(null);

export interface DouveryAuthProviderProps {
  config: DouveryAuthConfig;
  children: ReactNode;
  client?: DouveryAuthClient;
  onAuthenticated?: (user: User) => void;
  onLogout?: () => void;
  onError?: (error: Error) => void;
}

export function DouveryAuthProvider({
  config,
  children,
  client: externalClient,
  onAuthenticated,
  onLogout,
  onError,
}: DouveryAuthProviderProps) {
  const [client] = useState(() => externalClient || createDouveryAuth(config));
  const [state, setState] = useState<AuthState>(client.getState());
  const [isInitialized, setIsInitialized] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    let mounted = true;
    const initialize = async () => {
      try {
        await client.initialize();
        if (mounted) {
          setIsInitialized(true);
          setState(client.getState());
        }
      } catch (err) {
        if (mounted) {
          const e = err instanceof Error ? err : new Error(String(err));
          setError(e);
          onError?.(e);
        }
      }
    };
    initialize();
    return () => {
      mounted = false;
    };
  }, [client, onError]);

  useEffect(() => {
    const unsubscribe = client.subscribe((event) => {
      setState(client.getState());

      if (event.type === "LOGIN_SUCCESS") {
        onAuthenticated?.(event.user);
      } else if (event.type === "LOGOUT_SUCCESS") {
        onLogout?.();
      } else if (
        event.type === "LOGIN_ERROR" ||
        event.type === "LOGOUT_ERROR" ||
        event.type === "TOKEN_REFRESH_ERROR"
      ) {
        setError(event.error);
        onError?.(event.error);
      }
    });
    return unsubscribe;
  }, [client, onAuthenticated, onLogout, onError]);

  const login = useCallback(
    async (options?: LoginOptions) => {
      setIsLoading(true);
      setError(null);
      try {
        await client.login(options);
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        onError?.(e);
        throw e;
      } finally {
        setIsLoading(false);
      }
    },
    [client, onError],
  );

  const logout = useCallback(
    async (options?: LogoutOptions) => {
      setIsLoading(true);
      setError(null);
      try {
        await client.logout(options);
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        onError?.(e);
        throw e;
      } finally {
        setIsLoading(false);
      }
    },
    [client, onError],
  );

  const getAccessToken = useCallback(() => client.getAccessToken(), [client]);

  const refreshTokens = useCallback(async () => {
    setIsLoading(true);
    try {
      await client.refreshTokens();
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      setError(e);
      onError?.(e);
      throw e;
    } finally {
      setIsLoading(false);
    }
  }, [client, onError]);

  const value = useMemo<DouveryAuthContextValue>(
    () => ({
      state,
      isInitialized,
      isLoading,
      user: state.user,
      isAuthenticated: state.status === "authenticated",
      accessToken: state.tokens?.accessToken ?? null,
      error,
      login,
      logout,
      getAccessToken,
      refreshTokens,
      client,
    }),
    [
      state,
      isInitialized,
      isLoading,
      error,
      login,
      logout,
      getAccessToken,
      refreshTokens,
      client,
    ],
  );

  return (
    <DouveryAuthContext.Provider value={value}>
      {children}
    </DouveryAuthContext.Provider>
  );
}

export function useDouveryAuth(): DouveryAuthContextValue {
  const context = useContext(DouveryAuthContext);
  if (context === null) {
    throw new Error("useDouveryAuth must be used within DouveryAuthProvider");
  }
  return context;
}

export function useUser(): User | null {
  return useDouveryAuth().user;
}

export function useIsAuthenticated(): boolean {
  return useDouveryAuth().isAuthenticated;
}

export function useAccessToken() {
  const { accessToken, getAccessToken } = useDouveryAuth();
  return { accessToken, getAccessToken };
}

export function useAuthActions() {
  const { login, logout, isLoading } = useDouveryAuth();
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
