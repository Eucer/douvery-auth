# @douvery/auth

SDK de autenticación basada en sesión para Douvery.

## Principios

- El frontend nunca maneja tokens.
- El refresh ocurre solo en el backend.
- La cookie solo identifica la sesión.
- Esto funciona como Google Account.

## Instalación

```bash
npm install @douvery/auth
```

## API Core

### `createSessionClient(config?)`

Crea un cliente ligero para integrarse con endpoints backend session-based.

```ts
import { createSessionClient } from "@douvery/auth";

const auth = createSessionClient({
  baseUrl: "",
  sessionEndpoint: "/api/auth/session",
  logoutEndpoint: "/api/auth/logout",
  switchAccountEndpoint: "/api/auth/switch-account",
});

const session = await auth.getSession();
await auth.logout();
await auth.switchAccount("account_123");

auth.onSessionExpired((event) => {
  if (event.type === "SESSION_EXPIRED") {
    window.location.href = "/auth/login";
  }
});
```

### Funciones directas

```ts
import { getSession, logout, switchAccount } from "@douvery/auth";

const state = await getSession();
await logout();
await switchAccount("account_123");
```

## Qwik

### `useProvideSession()`

```tsx
import { component$, Slot, $ } from "@builder.io/qwik";
import { useProvideSession } from "@douvery/auth/qwik";

export default component$(() => {
  useProvideSession({
    config$: $(() => ({
      sessionEndpoint: "/api/auth/session",
      logoutEndpoint: "/api/auth/logout",
      switchAccountEndpoint: "/api/auth/switch-account",
    })),
  });

  return (
    <Slot />
  );
});
```

### `useSession()`

```tsx
import { component$ } from "@builder.io/qwik";
import { useSession } from "@douvery/auth/qwik";

export const SessionStatus = component$(() => {
  const { state, getSession, logout, switchAccount } = useSession();

  return (
    <div>
      <p>Estado: {state.value.status}</p>
      <button onClick$={() => getSession()}>Refrescar sesión</button>
      <button onClick$={() => logout()}>Cerrar sesión</button>
      <button onClick$={() => switchAccount("account_123")}>Cambiar cuenta</button>
    </div>
  );
});
```

## Server-side

Submódulo `@douvery/auth/session` para guards y operaciones de sesión en backend.

```ts
import { createSessionService } from "@douvery/auth/session";

const service = createSessionService({
  sessionApiUrl: "http://localhost:9924/api/session",
  cookieName: "douvery-session",
});

const result = await service.requireAuth(cookieAdapter, {
  redirectTo: "/auth/login",
});

if (!result.ok) {
  // redireccionar a result.redirectTo
}
```

## API pública

- Core:
  - `createSessionClient`
  - `getSession`
  - `logout`
  - `switchAccount`
  - `DouverySessionClient#onSessionExpired`
- Qwik:
  - `useProvideSession`
  - `useSession`
  - `createQwikSessionAdapter`
- Session server:
  - `createSessionService`
  - `requireAuth`

## Importante

Este paquete no implementa OAuth en frontend, no usa PKCE en browser, no almacena access/refresh/id tokens y no ejecuta refresh desde cliente.
