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
  selectAccount: (options?: SelectAccountOptions) => void;
  addAccount: (options?: AddAccountOptions) => void;
  register: (options?: RegisterOptions) => void;
  recoverAccount: (options?: RecoverAccountOptions) => void;
  verifyAccount: (options?: VerifyAccountOptions) => void;
  upgradeAccount: (options?: UpgradeAccountOptions) => void;
  setupPasskey: (options?: SetupPasskeyOptions) => void;
  setupAddress: (options?: SetupAddressOptions) => void;
  revokeToken: (options?: RevokeTokenOptions) => Promise<void>;
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

  const selectAccount = useCallback(
    (options?: SelectAccountOptions) => client.selectAccount(options),
    [client],
  );

  const addAccount = useCallback(
    (options?: AddAccountOptions) => client.addAccount(options),
    [client],
  );

  const register = useCallback(
    (options?: RegisterOptions) => client.register(options),
    [client],
  );

  const recoverAccount = useCallback(
    (options?: RecoverAccountOptions) => client.recoverAccount(options),
    [client],
  );

  const verifyAccount = useCallback(
    (options?: VerifyAccountOptions) => client.verifyAccount(options),
    [client],
  );

  const upgradeAccount = useCallback(
    (options?: UpgradeAccountOptions) => client.upgradeAccount(options),
    [client],
  );

  const setupPasskey = useCallback(
    (options?: SetupPasskeyOptions) => client.setupPasskey(options),
    [client],
  );

  const setupAddress = useCallback(
    (options?: SetupAddressOptions) => client.setupAddress(options),
    [client],
  );

  const revokeToken = useCallback(
    async (options?: RevokeTokenOptions) => {
      setIsLoading(true);
      setError(null);
      try {
        await client.revokeToken(options);
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
      selectAccount,
      addAccount,
      register,
      recoverAccount,
      verifyAccount,
      upgradeAccount,
      setupPasskey,
      setupAddress,
      revokeToken,
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
      selectAccount,
      addAccount,
      register,
      recoverAccount,
      verifyAccount,
      upgradeAccount,
      setupPasskey,
      setupAddress,
      revokeToken,
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
  const {
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
  } = useDouveryAuth();
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
  return useMemo(
    () => ({
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
    }),
    [client],
  );
}

/** Get session status helpers */
export function useSessionStatus() {
  const { client, state } = useDouveryAuth();
  return useMemo(
    () => ({
      isExpired: client.isSessionExpired(),
      needsVerification: client.needsEmailVerification(),
      isGuest: client.isGuestAccount(),
    }),
    [client, state],
  );
}

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
} from "@douvery/auth";
