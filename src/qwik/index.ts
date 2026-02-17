import {
  $,
  createContextId,
  noSerialize,
  type NoSerialize,
  type QRL,
  type Signal,
  useContext,
  useContextProvider,
  useSignal,
  useVisibleTask$,
} from "@builder.io/qwik";
import {
  createSessionClient,
  type CookieAdapter,
  type CookieSetOptions,
  type DouverySessionClient,
  type SessionClientConfig,
  type SessionEvent,
  type SessionState,
} from "@douvery/auth";

interface SessionContextValue {
  state: Signal<SessionState>;
  isLoading: Signal<boolean>;
  isInitialized: Signal<boolean>;
  clientRef: Signal<NoSerialize<DouverySessionClient> | undefined>;
}

export interface UserContextFactoryOptions<TUser> {
  contextId?: string;
  getInitialUser: () => TUser | null;
  refreshUser: () => Promise<TUser | null>;
  isAuthenticated?: (user: TUser | null) => boolean;
}

export interface UserContextActions<TUser> {
  updateUser: (nextUser: TUser | null) => void;
  refreshUser: () => Promise<TUser | null>;
}

export interface UserContextValue<TUser> {
  user: Signal<TUser | null>;
  isAuthenticated: Signal<boolean>;
}

export const DouverySessionContext =
  createContextId<SessionContextValue>("douvery-session");

const DEFAULT_STATE: SessionState = {
  status: "loading",
  user: null,
  session: null,
  error: null,
  checkedAt: null,
};

export interface ProvideSessionOptions {
  config$?: QRL<() => SessionClientConfig>;
  initialState?: SessionState;
}

export function useProvideSession(options: ProvideSessionOptions = {}) {
  const state = useSignal<SessionState>(options.initialState ?? DEFAULT_STATE);
  const isLoading = useSignal(false);
  const isInitialized = useSignal(false);
  const clientRef = useSignal<NoSerialize<DouverySessionClient>>();

  useContextProvider(DouverySessionContext, {
    state,
    isLoading,
    isInitialized,
    clientRef,
  });

  useVisibleTask$(async () => {
    const config = options.config$ ? await options.config$() : {};
    const client = createSessionClient(config);
    clientRef.value = noSerialize(client);

    const unsubscribe = client.subscribe((event: SessionEvent) => {
      if (
        event.type === "SESSION_UPDATED" ||
        event.type === "SESSION_EXPIRED"
      ) {
        state.value = event.state;
      }
      if (event.type === "SESSION_ERROR") {
        state.value = {
          ...state.value,
          error: event.error,
          checkedAt: Date.now(),
        };
      }
    });

    isLoading.value = true;
    state.value = await client.getSession();
    isLoading.value = false;
    isInitialized.value = true;

    return () => {
      unsubscribe();
      client.dispose();
    };
  });

  return {
    state,
    isLoading,
    isInitialized,
  };
}

function getClient(ctx: SessionContextValue): DouverySessionClient {
  const client = ctx.clientRef.value;
  if (!client) {
    throw new Error(
      "Douvery session client is not initialized. Ensure useProvideSession() has run in a hydrated component.",
    );
  }
  return client;
}

export function useSessionContext() {
  return useContext(DouverySessionContext);
}

export function useSession() {
  const ctx = useSessionContext();

  const refresh = $(async () => {
    ctx.isLoading.value = true;
    try {
      ctx.state.value = await getClient(ctx).getSession({ bypassCache: true });
      return ctx.state.value;
    } finally {
      ctx.isLoading.value = false;
    }
  });

  const logout = $(async () => {
    ctx.isLoading.value = true;
    try {
      await getClient(ctx).logout();
      ctx.state.value = getClient(ctx).getState();
    } finally {
      ctx.isLoading.value = false;
    }
  });

  const switchAccount = $(async (accountId: string) => {
    ctx.isLoading.value = true;
    try {
      ctx.state.value = await getClient(ctx).switchAccount(accountId);
      return ctx.state.value;
    } finally {
      ctx.isLoading.value = false;
    }
  });

  const onSessionExpired = $((handler: (event: SessionEvent) => void) => {
    return getClient(ctx).onSessionExpired((event: SessionEvent) => {
      if (event.type === "SESSION_EXPIRED") {
        handler(event);
      }
    });
  });

  return {
    state: ctx.state,
    isLoading: ctx.isLoading,
    isInitialized: ctx.isInitialized,
    getSession: refresh,
    logout,
    switchAccount,
    onSessionExpired,
  };
}

export function createUserContext<TUser>(
  options: UserContextFactoryOptions<TUser>,
) {
  const evaluateAuthenticated =
    options.isAuthenticated ?? ((user: TUser | null) => !!user);

  const UserContext = createContextId<UserContextValue<TUser>>(
    options.contextId ?? "douvery-user-context",
  );

  function useProvideUserContext() {
    const initialUser = options.getInitialUser();
    const user = useSignal<TUser | null>(initialUser);
    const isAuthenticated = useSignal<boolean>(
      evaluateAuthenticated(initialUser),
    );

    const updateUser = (nextUser: TUser | null) => {
      user.value = nextUser;
      isAuthenticated.value = evaluateAuthenticated(nextUser);
    };

    const refreshUser = async (): Promise<TUser | null> => {
      const nextUser = await options.refreshUser();
      updateUser(nextUser);
      return nextUser;
    };

    useContextProvider(UserContext, {
      user,
      isAuthenticated,
    });

    return {
      user,
      isAuthenticated,
      updateUser,
      refreshUser,
    };
  }

  function useUser() {
    const context = useContext(UserContext);
    return {
      user: context.user,
      isAuthenticated: context.isAuthenticated,
    };
  }

  function useUserActions() {
    const context = useContext(UserContext);

    const updateUser = (nextUser: TUser | null) => {
      context.user.value = nextUser;
      context.isAuthenticated.value = evaluateAuthenticated(nextUser);
    };

    const refreshUser = async (): Promise<TUser | null> => {
      const nextUser = await options.refreshUser();
      updateUser(nextUser);
      return nextUser;
    };

    return {
      user: context.user,
      isAuthenticated: context.isAuthenticated,
      updateUser,
      refreshUser,
    };
  }

  return {
    UserContext,
    useProvideUserContext,
    useUser,
    useUserActions,
  };
}

export { createQwikSessionAdapter } from "./session";

export type {
  SessionClientConfig,
  SessionState,
  SessionEvent,
  CookieAdapter,
  CookieSetOptions,
};
