/**
 * @douvery/auth - Token Storage
 * Abstraction for token persistence
 */

import type { TokenStorage, StorageKeys, TokenInfo } from "./types";

const DEFAULT_PREFIX = "douvery_auth";

export const STORAGE_KEYS: StorageKeys = {
  accessToken: `${DEFAULT_PREFIX}_access_token`,
  refreshToken: `${DEFAULT_PREFIX}_refresh_token`,
  idToken: `${DEFAULT_PREFIX}_id_token`,
  expiresAt: `${DEFAULT_PREFIX}_expires_at`,
  state: `${DEFAULT_PREFIX}_state`,
  nonce: `${DEFAULT_PREFIX}_nonce`,
  codeVerifier: `${DEFAULT_PREFIX}_code_verifier`,
  returnTo: `${DEFAULT_PREFIX}_return_to`,
};

/** In-memory storage implementation */
export class MemoryStorage implements TokenStorage {
  private store = new Map<string, string>();

  get(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  set(key: string, value: string): void {
    this.store.set(key, value);
  }

  remove(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }
}

/** LocalStorage implementation */
export class LocalStorage implements TokenStorage {
  get(key: string): string | null {
    if (typeof window === "undefined") return null;
    return localStorage.getItem(key);
  }

  set(key: string, value: string): void {
    if (typeof window === "undefined") return;
    localStorage.setItem(key, value);
  }

  remove(key: string): void {
    if (typeof window === "undefined") return;
    localStorage.removeItem(key);
  }

  clear(): void {
    if (typeof window === "undefined") return;
    Object.values(STORAGE_KEYS).forEach((key) => {
      localStorage.removeItem(key);
    });
  }
}

/** SessionStorage implementation */
export class SessionStorage implements TokenStorage {
  get(key: string): string | null {
    if (typeof window === "undefined") return null;
    return sessionStorage.getItem(key);
  }

  set(key: string, value: string): void {
    if (typeof window === "undefined") return;
    sessionStorage.setItem(key, value);
  }

  remove(key: string): void {
    if (typeof window === "undefined") return;
    sessionStorage.removeItem(key);
  }

  clear(): void {
    if (typeof window === "undefined") return;
    Object.values(STORAGE_KEYS).forEach((key) => {
      sessionStorage.removeItem(key);
    });
  }
}

/** Cookie storage implementation (for SSR compatibility) */
export class CookieStorage implements TokenStorage {
  constructor(
    private options: {
      path?: string;
      domain?: string;
      secure?: boolean;
      sameSite?: "Strict" | "Lax" | "None";
      maxAge?: number;
    } = {},
  ) {
    this.options = { path: "/", secure: true, sameSite: "Lax", ...options };
  }

  get(key: string): string | null {
    if (typeof document === "undefined") return null;
    const cookies = document.cookie.split(";");
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split("=");
      if (name === key) {
        return decodeURIComponent(value);
      }
    }
    return null;
  }

  set(key: string, value: string): void {
    if (typeof document === "undefined") return;
    const parts = [
      `${key}=${encodeURIComponent(value)}`,
      `path=${this.options.path}`,
    ];
    if (this.options.domain) parts.push(`domain=${this.options.domain}`);
    if (this.options.secure) parts.push("secure");
    if (this.options.sameSite) parts.push(`samesite=${this.options.sameSite}`);
    if (this.options.maxAge) parts.push(`max-age=${this.options.maxAge}`);
    document.cookie = parts.join("; ");
  }

  remove(key: string): void {
    if (typeof document === "undefined") return;
    document.cookie = `${key}=; path=${this.options.path}; expires=Thu, 01 Jan 1970 00:00:00 GMT`;
  }

  clear(): void {
    Object.values(STORAGE_KEYS).forEach((key) => this.remove(key));
  }
}

/** Create storage instance based on type */
export function createStorage(
  type: "localStorage" | "sessionStorage" | "memory" | "cookie",
): TokenStorage {
  switch (type) {
    case "localStorage":
      return new LocalStorage();
    case "sessionStorage":
      return new SessionStorage();
    case "cookie":
      return new CookieStorage();
    case "memory":
    default:
      return new MemoryStorage();
  }
}

/** Token manager for handling token persistence */
export class TokenManager {
  constructor(private storage: TokenStorage) {}

  async getTokens(): Promise<TokenInfo | null> {
    const accessToken = await this.storage.get(STORAGE_KEYS.accessToken);
    if (!accessToken) return null;

    const refreshToken = await this.storage.get(STORAGE_KEYS.refreshToken);
    const idToken = await this.storage.get(STORAGE_KEYS.idToken);
    const expiresAt = await this.storage.get(STORAGE_KEYS.expiresAt);

    return {
      accessToken,
      refreshToken: refreshToken ?? undefined,
      idToken: idToken ?? undefined,
      expiresAt: expiresAt ? parseInt(expiresAt, 10) : 0,
      tokenType: "Bearer",
      scope: [],
    };
  }

  async setTokens(tokens: TokenInfo): Promise<void> {
    await this.storage.set(STORAGE_KEYS.accessToken, tokens.accessToken);
    await this.storage.set(STORAGE_KEYS.expiresAt, tokens.expiresAt.toString());
    if (tokens.refreshToken) {
      await this.storage.set(STORAGE_KEYS.refreshToken, tokens.refreshToken);
    }
    if (tokens.idToken) {
      await this.storage.set(STORAGE_KEYS.idToken, tokens.idToken);
    }
  }

  async clearTokens(): Promise<void> {
    await this.storage.remove(STORAGE_KEYS.accessToken);
    await this.storage.remove(STORAGE_KEYS.refreshToken);
    await this.storage.remove(STORAGE_KEYS.idToken);
    await this.storage.remove(STORAGE_KEYS.expiresAt);
  }

  async saveState(state: string): Promise<void> {
    await this.storage.set(STORAGE_KEYS.state, state);
  }

  async getState(): Promise<string | null> {
    return this.storage.get(STORAGE_KEYS.state);
  }

  async clearState(): Promise<void> {
    await this.storage.remove(STORAGE_KEYS.state);
  }

  async saveNonce(nonce: string): Promise<void> {
    await this.storage.set(STORAGE_KEYS.nonce, nonce);
  }

  async getNonce(): Promise<string | null> {
    return this.storage.get(STORAGE_KEYS.nonce);
  }

  async clearNonce(): Promise<void> {
    await this.storage.remove(STORAGE_KEYS.nonce);
  }

  async saveCodeVerifier(verifier: string): Promise<void> {
    await this.storage.set(STORAGE_KEYS.codeVerifier, verifier);
  }

  async getCodeVerifier(): Promise<string | null> {
    return this.storage.get(STORAGE_KEYS.codeVerifier);
  }

  async clearCodeVerifier(): Promise<void> {
    await this.storage.remove(STORAGE_KEYS.codeVerifier);
  }

  async saveReturnTo(url: string): Promise<void> {
    await this.storage.set(STORAGE_KEYS.returnTo, url);
  }

  async getReturnTo(): Promise<string | null> {
    return this.storage.get(STORAGE_KEYS.returnTo);
  }

  async clearReturnTo(): Promise<void> {
    await this.storage.remove(STORAGE_KEYS.returnTo);
  }

  async clearAll(): Promise<void> {
    await this.storage.clear();
  }
}

// ============================================================================
// Server-Bridged Storage
// ============================================================================

/**
 * Options for createServerBridgedStorage.
 *
 * Use this when tokens are managed server-side (httpOnly cookies)
 * but the OAuth/PKCE flow needs client-side ephemeral storage.
 */
export interface ServerBridgedStorageOptions {
  /**
   * Name of a **non-httpOnly** cookie that holds the access token
   * expiration timestamp (in milliseconds). Used to infer whether
   * a valid session exists without exposing the actual tokens.
   */
  tokenExpirationCookie: string;

  /**
   * Placeholder value returned by `get()` for server-managed keys
   * (accessToken, refreshToken). Signals to the caller that the
   * real token exists but is not readable from JS.
   * @default "__server_managed__"
   */
  serverManagedPlaceholder?: string;

  /**
   * Enable debug logging.
   * @default false
   */
  debug?: boolean;
}

/** Keys whose real values live in httpOnly cookies */
const SERVER_TOKEN_KEYS = new Set([
  STORAGE_KEYS.accessToken,
  STORAGE_KEYS.refreshToken,
  STORAGE_KEYS.idToken,
]);

/** Keys that are ephemeral to the OAuth/PKCE flow */
const PKCE_KEYS = new Set([
  STORAGE_KEYS.state,
  STORAGE_KEYS.nonce,
  STORAGE_KEYS.codeVerifier,
  STORAGE_KEYS.returnTo,
]);

/**
 * Read a cookie by name from `document.cookie` (client-side only).
 * Returns null during SSR or if the cookie is not found.
 */
function readClientCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const cookies = document.cookie.split(";");
  for (const c of cookies) {
    const [key, ...parts] = c.trim().split("=");
    if (key === name) return decodeURIComponent(parts.join("="));
  }
  return null;
}

/** Safe sessionStorage accessor (no-op in SSR). */
function safeSessionStorage(): globalThis.Storage | null {
  if (typeof window === "undefined" || typeof sessionStorage === "undefined") {
    return null;
  }
  return sessionStorage;
}

/**
 * Creates a `TokenStorage` adapter for apps where **tokens are
 * managed server-side** (e.g. httpOnly cookies set by routeLoader$/
 * routeAction$) but the OAuth PKCE flow still needs ephemeral
 * client-side storage for state, nonce, codeVerifier and returnTo.
 *
 * Behaviour per key category:
 *
 * | Category          | get()                                    | set() / remove() |
 * |-------------------|------------------------------------------|-------------------|
 * | accessToken       | returns placeholder if session is active | no-op (server)    |
 * | refreshToken      | returns placeholder if session exists    | no-op (server)    |
 * | idToken           | always null                              | no-op             |
 * | expiresAt         | reads from expiration cookie             | no-op (server)    |
 * | state/nonce/etc.  | sessionStorage                           | sessionStorage    |
 *
 * @example
 * ```ts
 * import { createServerBridgedStorage } from '@douvery/auth';
 *
 * const bridgedStorage = createServerBridgedStorage({
 *   tokenExpirationCookie: 'dou_token_exp',
 *   debug: import.meta.env.DEV,
 * });
 *
 * const config: DouveryAuthConfig = {
 *   clientId: 'my-app',
 *   redirectUri: '/callback',
 *   customStorage: bridgedStorage,
 *   autoRefresh: false, // server handles refresh
 * };
 * ```
 */
export function createServerBridgedStorage(
  options: ServerBridgedStorageOptions,
): TokenStorage {
  const {
    tokenExpirationCookie,
    serverManagedPlaceholder = "__server_managed__",
    debug = false,
  } = options;

  function log(msg: string) {
    if (debug) console.debug(`[ServerBridgedStorage] ${msg}`);
  }

  return {
    get(key: string): string | null {
      // -- Access token: infer from expiration cookie --
      if (key === STORAGE_KEYS.accessToken) {
        const exp = readClientCookie(tokenExpirationCookie);
        if (exp) {
          const ms = parseInt(exp, 10);
          if (!isNaN(ms) && ms > Date.now()) return serverManagedPlaceholder;
        }
        return null;
      }

      // -- Refresh token: infer existence from expiration cookie --
      if (key === STORAGE_KEYS.refreshToken) {
        const exp = readClientCookie(tokenExpirationCookie);
        return exp ? serverManagedPlaceholder : null;
      }

      // -- ID token: not stored in this system --
      if (key === STORAGE_KEYS.idToken) return null;

      // -- Expiration timestamp --
      if (key === STORAGE_KEYS.expiresAt) {
        return readClientCookie(tokenExpirationCookie);
      }

      // -- PKCE/ephemeral keys -> sessionStorage --
      if (PKCE_KEYS.has(key)) {
        return safeSessionStorage()?.getItem(key) ?? null;
      }

      // -- Fallback: sessionStorage for unknown keys --
      return safeSessionStorage()?.getItem(key) ?? null;
    },

    set(key: string, value: string): void {
      if (SERVER_TOKEN_KEYS.has(key) || key === STORAGE_KEYS.expiresAt) {
        log(`Ignoring set("${key}") – managed by server`);
        return;
      }
      const ss = safeSessionStorage();
      if (ss) {
        try {
          ss.setItem(key, value);
        } catch (e) {
          if (debug)
            console.warn(
              "[ServerBridgedStorage] sessionStorage.setItem failed:",
              e,
            );
        }
      }
    },

    remove(key: string): void {
      if (SERVER_TOKEN_KEYS.has(key) || key === STORAGE_KEYS.expiresAt) {
        log(`Ignoring remove("${key}") – managed by server`);
        return;
      }
      const ss = safeSessionStorage();
      if (ss) {
        try {
          ss.removeItem(key);
        } catch (e) {
          if (debug)
            console.warn(
              "[ServerBridgedStorage] sessionStorage.removeItem failed:",
              e,
            );
        }
      }
    },

    clear(): void {
      const ss = safeSessionStorage();
      if (!ss) return;
      for (const key of PKCE_KEYS) {
        try {
          ss.removeItem(key);
        } catch {
          // silently ignore
        }
      }
      log("PKCE ephemeral data cleared from sessionStorage");
    },
  };
}
