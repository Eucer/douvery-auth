# @douvery/auth

<p align="center">
  <img src="https://img.shields.io/npm/v/@douvery/auth?style=flat-square&color=blue" alt="npm version" />
  <img src="https://img.shields.io/npm/dm/@douvery/auth?style=flat-square&color=green" alt="downloads" />
  <img src="https://img.shields.io/npm/l/@douvery/auth?style=flat-square" alt="license" />
  <img src="https://img.shields.io/badge/TypeScript-5.0+-blue?style=flat-square&logo=typescript" alt="typescript" />
</p>

<p align="center">
  <strong>🔐 OAuth 2.0/OIDC client library for Douvery authentication</strong>
</p>

<p align="center">
  Secure, type-safe authentication with PKCE support for React, Qwik, and vanilla TypeScript.
</p>

---

## ✨ Features

- 🔒 **PKCE Support** - Secure authorization code flow with Proof Key for Code Exchange
- 🔄 **Auto Token Refresh** - Automatic token refresh before expiry
- 💾 **Multiple Storage Options** - localStorage, sessionStorage, memory, or cookies
- 📦 **Tree Shakeable** - Import only what you need
- 🎯 **TypeScript First** - Full TypeScript support with comprehensive types
- ⚛️ **React Adapter** - Provider and hooks for React 18+
- ⚡ **Qwik Adapter** - Signal-based reactivity for Qwik
- 📡 **Event System** - Subscribe to auth events (login, logout, token refresh)
- 🌐 **SSR Compatible** - Works with server-side rendering
- 🪶 **Lightweight** - ~23KB core, framework adapters add minimal overhead
- 🧭 **Auth Navigation** - Built-in helpers for all auth flows (register, recover, verify, switch account, etc.)
- 🔗 **URL Builders** - Generate auth URLs for `<a>` tags without programmatic redirect
- 🔑 **Token Revocation** - Revoke access/refresh tokens via RFC 7009

---

## 📦 Installation

```bash
# npm
npm install @douvery/auth

# pnpm
pnpm add @douvery/auth

# bun
bun add @douvery/auth

# yarn
yarn add @douvery/auth
```

### Peer Dependencies (Optional)

- **React**: `react >= 18.0.0` (only if using `@douvery/auth/react`)
- **Qwik**: `@builder.io/qwik >= 1.0.0` (only if using `@douvery/auth/qwik`)

---

## 🚀 Quick Start

### React

```tsx
import { DouveryAuthProvider, useDouveryAuth, useUser } from '@douvery/auth/react';

// 1. Wrap your app with the provider
function App() {
  return (
    <DouveryAuthProvider
      config={{
        clientId: 'your-client-id',
        redirectUri: window.location.origin + '/callback',
        issuer: 'https://auth.douvery.com',
        scopes: ['openid', 'profile', 'email'],
      }}
      onAuthenticated={(user) => console.log('Logged in:', user)}
      onLogout={() => console.log('Logged out')}
      onError={(error) => console.error('Auth error:', error)}
    >
      <YourApp />
    </DouveryAuthProvider>
  );
}

// 2. Use hooks in your components
function LoginButton() {
  const { login, logout, isAuthenticated, isLoading } = useDouveryAuth();
  const user = useUser();

  if (isLoading) return <span>Loading...</span>;

  if (isAuthenticated) {
    return (
      <div>
        <img src={user?.picture} alt={user?.name} />
        <p>Welcome, {user?.name}!</p>
        <button onClick={() => logout()}>Logout</button>
      </div>
    );
  }

  return <button onClick={() => login()}>Login with Douvery</button>;
}
```

### Qwik

```tsx
import { DouveryAuthProvider, useDouveryAuth, useUser, useAuthActions } from '@douvery/auth/qwik';
import { component$, Slot } from '@builder.io/qwik';

// 1. Wrap your app with the provider
export default component$(() => {
  return (
    <DouveryAuthProvider
      config={{
        clientId: 'your-client-id',
        redirectUri: 'http://localhost:5173/callback',
        issuer: 'https://auth.douvery.com',
        scopes: ['openid', 'profile', 'email'],
      }}
    >
      <Slot />
    </DouveryAuthProvider>
  );
});

// 2. Use hooks in your components (signal-based)
export const LoginButton = component$(() => {
  const user = useUser();
  const { login, logout, isLoading } = useAuthActions();

  return (
    <>
      {user.value ? (
        <div>
          <img src={user.value.picture} alt={user.value.name} />
          <p>Welcome, {user.value.name}!</p>
          <button onClick$={() => logout()}>Logout</button>
        </div>
      ) : (
        <button onClick$={() => login()} disabled={isLoading.value}>
          {isLoading.value ? 'Loading...' : 'Login with Douvery'}
        </button>
      )}
    </>
  );
});
```

### Vanilla TypeScript / JavaScript

```typescript
import { createDouveryAuth } from '@douvery/auth';

// 1. Create the auth client
const auth = createDouveryAuth({
  clientId: 'your-client-id',
  redirectUri: window.location.origin + '/callback',
  issuer: 'https://auth.douvery.com',
  scopes: ['openid', 'profile', 'email'],
});

// 2. Subscribe to auth events
auth.subscribe((event) => {
  switch (event.type) {
    case 'LOGIN_SUCCESS':
      console.log('Logged in:', event.user);
      break;
    case 'LOGOUT_SUCCESS':
      console.log('Logged out');
      break;
    case 'TOKEN_REFRESHED':
      console.log('Token refreshed');
      break;
    case 'SESSION_EXPIRED':
      console.log('Session expired');
      break;
  }
});

// 3. Initialize (handles callback if present, restores session)
await auth.initialize();

// 4. Check authentication state
const state = auth.getState();
console.log('Status:', state.status); // 'loading' | 'authenticated' | 'unauthenticated'
console.log('User:', state.user);

// 5. Login (redirects to auth server)
await auth.login({ returnTo: '/dashboard' });

// 6. Get access token (auto-refreshes if needed)
const token = await auth.getAccessToken();
fetch('/api/protected', {
  headers: { Authorization: `Bearer ${token}` }
});

// 7. Logout
await auth.logout();

// 8. Navigation helpers — redirect to any auth flow
auth.selectAccount({ returnTo: '/dashboard' });
auth.addAccount({ loginHint: 'other@email.com' });
auth.register({ email: 'new@email.com' });
auth.recoverAccount({ email: 'user@email.com' });
auth.verifyAccount();
auth.upgradeAccount();
auth.setupPasskey();
auth.setupAddress();

// 9. URL builders (don't redirect, useful for <a> tags)
const url = auth.buildSelectAccountUrl({ returnTo: '/home' });
console.log(url.url);   // "https://auth.douvery.com/select-account?continue=/home"
url.redirect();          // Navigate to the URL
url.open();              // Open in new tab

// 10. Revoke a token
await auth.revokeToken();
await auth.revokeToken({ tokenTypeHint: 'refresh_token' });

// 11. Session status helpers
auth.isSessionExpired();        // true/false
auth.needsEmailVerification();  // true/false
auth.isGuestAccount();          // true/false
```

---

## 📖 API Reference

### Configuration

```typescript
interface DouveryAuthConfig {
  /** OAuth Client ID (required) */
  clientId: string;

  /** Redirect URI after authentication (required) */
  redirectUri: string;

  /** Authorization server base URL */
  issuer?: string; // default: "https://auth.douvery.com"

  /** Post-logout redirect URI */
  postLogoutRedirectUri?: string;

  /** OAuth scopes to request */
  scopes?: string[]; // default: ["openid", "profile", "email"]

  /** Token storage strategy */
  storage?: "localStorage" | "sessionStorage" | "memory" | "cookie"; // default: "localStorage"

  /** Custom storage implementation */
  customStorage?: TokenStorage;

  /** Auto-refresh tokens before expiry */
  autoRefresh?: boolean; // default: true

  /** Seconds before expiry to trigger refresh */
  refreshThreshold?: number; // default: 60

  /** Enable debug logging */
  debug?: boolean; // default: false
}
```

### Login Options

```typescript
await auth.login({
  // URL to return to after login
  returnTo: '/dashboard',

  // Force re-authentication or consent
  prompt: 'login' | 'consent' | 'select_account' | 'none',

  // Pre-fill email/username
  loginHint: 'user@example.com',

  // UI locale preference
  uiLocales: 'es',

  // Maximum authentication age in seconds
  maxAge: 3600,

  // Additional authorization parameters
  authorizationParams: {
    audience: 'https://api.example.com',
  },
});
```

### Logout Options

```typescript
await auth.logout({
  // URL to return to after logout
  returnTo: 'https://example.com',

  // End session at IdP (federated logout)
  federated: true, // default: true

  // Only clear local session, don't redirect
  localOnly: false, // default: false
});
```

### Navigation Options

All navigation methods accept a common base of options:

```typescript
interface AuthNavigationOptions {
  returnTo?: string;      // URL to return to after the action
  clientId?: string;      // OAuth client_id for branded experiences
  openInNewTab?: boolean; // Open in new tab instead of redirect
}
```

```typescript
// Select / switch account
auth.selectAccount({
  returnTo: '/dashboard',
  loginHint: 'user@email.com', // Pre-select a specific account
});

// Add another account (multi-session)
auth.addAccount({
  loginHint: 'another@email.com',
});

// Register a new account
auth.register({
  email: 'new@email.com',
  firstName: 'John',
  lastName: 'Doe',
  uiLocales: 'es',
});

// Recover account (forgot password)
auth.recoverAccount({
  email: 'user@email.com',
});

// Verify account (email verification)
auth.verifyAccount({
  email: 'user@email.com',
});

// Upgrade guest account to full account
auth.upgradeAccount({
  scopes: ['profile', 'email'],
});

// Setup passkey
auth.setupPasskey({ returnTo: '/settings' });

// Setup address
auth.setupAddress({ returnTo: '/checkout' });
```

### URL Builders

Every navigation method has a corresponding `build*Url()` method that returns an `AuthUrl` object without redirecting. Useful for `<a>` tags or custom navigation logic:

```typescript
const url = auth.buildRegisterUrl({ email: 'hint@test.com' });

url.url;        // "https://auth.douvery.com/register?email=hint%40test.com"
url.redirect(); // window.location.href = url
url.open();     // window.open(url, '_blank')
```

| Builder | Path |
|---|---|
| `buildLoginUrl()` | `/login` |
| `buildLogoutUrl()` | `/logout` |
| `buildSelectAccountUrl()` | `/select-account` |
| `buildAddAccountUrl()` | `/login?add_account=true` |
| `buildRegisterUrl()` | `/register` |
| `buildRecoverAccountUrl()` | `/recover-account` |
| `buildVerifyAccountUrl()` | `/verify-account` |
| `buildUpgradeAccountUrl()` | `/upgrade-account` |
| `buildSetupPasskeyUrl()` | `/setup-passkey` |
| `buildSetupAddressUrl()` | `/setup-address` |

### Token Revocation

```typescript
// Revoke current access token
await auth.revokeToken();

// Revoke a specific token
await auth.revokeToken({
  token: 'specific-token-value',
  tokenTypeHint: 'refresh_token',
});
```

### Session Status Helpers

```typescript
auth.isSessionExpired();        // true if access token is expired
auth.needsEmailVerification();  // true if email is not verified
auth.isGuestAccount();          // true if account type is guest
```

### Auth State

```typescript
interface AuthState {
  status: 'loading' | 'authenticated' | 'unauthenticated';
  user: User | null;
  tokens: TokenInfo | null;
  error: AuthError | null;
}

interface User {
  id: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  firstName?: string;
  lastName?: string;
  picture?: string;
  phoneNumber?: string;
  locale?: string;
  [key: string]: unknown;
}
```

### Auth Events

```typescript
type AuthEvent =
  | { type: 'INITIALIZED' }
  | { type: 'LOGIN_STARTED' }
  | { type: 'LOGIN_SUCCESS'; user: User; tokens: TokenInfo }
  | { type: 'LOGIN_ERROR'; error: AuthError }
  | { type: 'LOGOUT_STARTED' }
  | { type: 'LOGOUT_SUCCESS' }
  | { type: 'LOGOUT_ERROR'; error: AuthError }
  | { type: 'TOKEN_REFRESHED'; tokens: TokenInfo }
  | { type: 'TOKEN_REFRESH_ERROR'; error: AuthError }
  | { type: 'SESSION_EXPIRED' };
```

---

## 🪝 React Hooks

| Hook | Description |
|------|-------------|
| `useDouveryAuth()` | Full context with state, actions, and client |
| `useUser()` | Current user or null |
| `useIsAuthenticated()` | Boolean authentication status |
| `useAccessToken()` | `{ accessToken, getAccessToken }` |
| `useAuthActions()` | All auth actions (see below) |
| `useAuthUrls()` | URL builders for all auth pages |
| `useSessionStatus()` | `{ isExpired, needsVerification, isGuest }` |

#### `useAuthActions()` — Full list

```tsx
const {
  login,           // (options?: LoginOptions) => Promise<void>
  logout,          // (options?: LogoutOptions) => Promise<void>
  selectAccount,   // (options?: SelectAccountOptions) => void
  addAccount,      // (options?: AddAccountOptions) => void
  register,        // (options?: RegisterOptions) => void
  recoverAccount,  // (options?: RecoverAccountOptions) => void
  verifyAccount,   // (options?: VerifyAccountOptions) => void
  upgradeAccount,  // (options?: UpgradeAccountOptions) => void
  setupPasskey,    // (options?: SetupPasskeyOptions) => void
  setupAddress,    // (options?: SetupAddressOptions) => void
  revokeToken,     // (options?: RevokeTokenOptions) => Promise<void>
  isLoading,       // boolean
} = useAuthActions();
```

#### `useAuthUrls()` — URL builders for links

```tsx
const urls = useAuthUrls();

<a href={urls.registerUrl().url}>Create account</a>
<a href={urls.recoverAccountUrl({ email: user.email }).url}>Forgot password?</a>
<a href={urls.selectAccountUrl().url}>Switch account</a>
```

#### `useSessionStatus()` — Reactive status

```tsx
const { isExpired, needsVerification, isGuest } = useSessionStatus();

{needsVerification && <Banner>Please verify your email</Banner>}
{isGuest && <button onClick={() => upgradeAccount()}>Upgrade account</button>}
```

### DouveryAuthProvider Props

```typescript
interface DouveryAuthProviderProps {
  config: DouveryAuthConfig;
  children: ReactNode;
  client?: DouveryAuthClient;        // Optional pre-configured client
  onAuthenticated?: (user: User) => void;
  onLogout?: () => void;
  onError?: (error: Error) => void;
}
```

---

## ⚡ Qwik Hooks

| Hook | Return Type | Description |
|------|-------------|-------------|
| `useDouveryAuth()` | Context | Full context with signals and client |
| `useUser()` | `Signal<User \| null>` | Reactive user signal |
| `useIsAuthenticated()` | `Signal<boolean>` | Reactive auth status |
| `useAuthActions()` | All actions + `isLoading` | Auth actions (same as React) |
| `useAuthUrls()` | URL builders | Build URLs for auth pages |
| `useSessionStatus()` | `{ isExpired, needsVerification, isGuest }` | Reactive session signals |

#### Qwik example with navigation

```tsx
import { component$ } from '@builder.io/qwik';
import { useAuthActions, useSessionStatus } from '@douvery/auth/qwik';

export const AccountMenu = component$(() => {
  const { selectAccount, addAccount, recoverAccount, upgradeAccount } = useAuthActions();
  const { isGuest, needsVerification } = useSessionStatus();

  return (
    <div>
      <button onClick$={() => selectAccount({ returnTo: window.location.href })}>
        Switch account
      </button>
      <button onClick$={() => addAccount()}>Add account</button>
      {isGuest.value && (
        <button onClick$={() => upgradeAccount()}>Upgrade account</button>
      )}
      {needsVerification.value && (
        <button onClick$={() => verifyAccount()}>Verify email</button>
      )}
    </div>
  );
});
```

---

## 🔒 Security Best Practices

### 1. Always Use HTTPS in Production
```typescript
const config = {
  redirectUri: 'https://yourapp.com/callback', // Not http://
};
```

### 2. Validate Redirect URIs
Register exact redirect URIs in your OAuth application settings.

### 3. Use Appropriate Storage
```typescript
// For high-security apps, use memory storage
const auth = createDouveryAuth({
  storage: 'memory', // Tokens cleared on page refresh
});

// For normal apps, localStorage is fine
const auth = createDouveryAuth({
  storage: 'localStorage', // Persists across tabs/sessions
});
```

### 4. Handle Token Expiry
```typescript
auth.subscribe((event) => {
  if (event.type === 'SESSION_EXPIRED') {
    // Redirect to login or show re-auth modal
    auth.login({ prompt: 'login' });
  }
});
```

---

## 🔧 Handling Callbacks

### React

```tsx
// pages/callback.tsx or routes/callback.tsx
import { useEffect } from 'react';
import { useDouveryAuth } from '@douvery/auth/react';
import { useNavigate } from 'react-router-dom';

export function CallbackPage() {
  const { isInitialized, isAuthenticated, error } = useDouveryAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isInitialized) {
      if (isAuthenticated) {
        navigate('/dashboard');
      } else if (error) {
        navigate('/login?error=' + error.message);
      }
    }
  }, [isInitialized, isAuthenticated, error, navigate]);

  return <div>Completing login...</div>;
}
```

### Qwik

```tsx
// routes/callback/index.tsx
import { component$ } from '@builder.io/qwik';
import { useNavigate } from '@builder.io/qwik-city';
import { useDouveryAuth } from '@douvery/auth/qwik';

export default component$(() => {
  const { isInitialized, state, error } = useDouveryAuth();
  const nav = useNavigate();

  useVisibleTask$(({ track }) => {
    track(() => isInitialized.value);
    if (isInitialized.value) {
      if (state.value.status === 'authenticated') {
        nav('/dashboard');
      } else if (error.value) {
        nav('/login?error=' + error.value.message);
      }
    }
  });

  return <div>Completing login...</div>;
});
```

---

## 🛠️ Advanced Usage

### Custom Storage

```typescript
import { createDouveryAuth, TokenStorage } from '@douvery/auth';

const secureStorage: TokenStorage = {
  get: (key) => secureStore.getItem(key),
  set: (key, value) => secureStore.setItem(key, value),
  remove: (key) => secureStore.removeItem(key),
  clear: () => secureStore.clear(),
};

const auth = createDouveryAuth({
  clientId: 'your-client-id',
  redirectUri: '/callback',
  customStorage: secureStorage,
});
```

### Pre-configured Client (React)

```tsx
import { DouveryAuthProvider } from '@douvery/auth/react';
import { createDouveryAuth } from '@douvery/auth';

// Create client once, outside component
const authClient = createDouveryAuth({
  clientId: 'your-client-id',
  redirectUri: '/callback',
});

function App() {
  return (
    <DouveryAuthProvider config={{}} client={authClient}>
      <YourApp />
    </DouveryAuthProvider>
  );
}
```

### API Request with Token

```typescript
async function fetchProtectedData() {
  const token = await auth.getAccessToken();
  
  if (!token) {
    throw new Error('Not authenticated');
  }

  const response = await fetch('https://api.example.com/data', {
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });

  if (response.status === 401) {
    // Token might be invalid, try to refresh
    await auth.refreshTokens();
    return fetchProtectedData();
  }

  return response.json();
}
```

---

## 📁 Package Structure

```
@douvery/auth
├── dist/
│   ├── index.js          # Core (ESM)
│   ├── index.d.ts        # Core types
│   ├── react/
│   │   ├── index.js      # React adapter
│   │   └── index.d.ts    # React types
│   └── qwik/
│       ├── index.js      # Qwik adapter
│       └── index.d.ts    # Qwik types
```

**Imports:**
```typescript
// Core
import { createDouveryAuth, DouveryAuthClient } from '@douvery/auth';

// React
import { DouveryAuthProvider, useDouveryAuth } from '@douvery/auth/react';

// Qwik
import { DouveryAuthProvider, useDouveryAuth } from '@douvery/auth/qwik';
```

---

## 🤝 Contributing

```bash
# Clone the repository
git clone https://github.com/douvery/douvery-auth.git
cd douvery-auth

# Install dependencies
bun install

# Build all packages
npm run build

# Run type checking
npx tsc --noEmit
```

---

## 📄 License

MIT © [Douvery](https://douvery.com)

---

<p align="center">
  Made with ❤️ by the Douvery team
</p>
