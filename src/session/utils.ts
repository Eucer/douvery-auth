/**
 * @douvery/auth - Session Utilities
 * Pure functions for JWT parsing, cache TTL computation, and fetch timeout
 */

/** Default fallback cache TTL: 30 seconds */
const DEFAULT_FALLBACK_CACHE_TTL_MS = 30_000;

/** Default fetch timeout: 3 seconds */
const DEFAULT_FETCH_TIMEOUT_MS = 3_000;

/**
 * Compute HMAC-SHA256 hex digest (synchronous, Node.js crypto).
 * Used for internal service authentication headers.
 *
 * Note: Uses dynamic require to avoid bundler issues. This function
 * is only called in SSR context where Node.js crypto is available.
 */
export function computeHmac(message: string, secret: string): string {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { createHmac } = require("crypto");
  return createHmac("sha256", secret).update(message).digest("hex");
}

/**
 * Extract `exp` claim from a JWT without full verification.
 * Returns the exp as Unix seconds, or undefined if parsing fails.
 *
 * This is a lightweight alternative to full JWT decoding when you
 * only need the expiration timestamp.
 */
export function parseJwtExp(token: string): number | undefined {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return undefined;

    const payload = JSON.parse(
      atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")),
    );
    return typeof payload.exp === "number" ? payload.exp : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Calculate cache TTL based on the JWT's `exp` claim.
 *
 * Strategy:
 * 1. If auth server provides `expires_in`, use 90% of that
 * 2. If JWT has `exp`, use 90% of remaining lifetime
 * 3. Fall back to `fallbackTtlMs`
 *
 * Result is clamped between 5s and 5min to prevent both
 * excessive polling and stale caches.
 */
export function computeCacheTTL(
  jwtExp: number | undefined,
  serverExpiresIn?: number,
  fallbackTtlMs: number = DEFAULT_FALLBACK_CACHE_TTL_MS,
): number {
  if (serverExpiresIn && serverExpiresIn > 0) {
    // Auth server told us exactly how long the token lives (in seconds)
    return Math.min(Math.max(serverExpiresIn * 0.9 * 1000, 5_000), 300_000);
  }

  if (jwtExp) {
    const remainingMs = jwtExp * 1000 - Date.now();
    if (remainingMs > 0) {
      return Math.min(Math.max(remainingMs * 0.9, 5_000), 300_000);
    }
  }

  return fallbackTtlMs;
}

/**
 * Fetch wrapper with AbortController timeout.
 * Prevents SSR from hanging if the auth server is unresponsive.
 *
 * @param url - The URL to fetch
 * @param options - Standard fetch RequestInit options
 * @param timeoutMs - Timeout in milliseconds (default: 3000)
 * @throws DOMException with name 'AbortError' on timeout
 */
export async function fetchWithTimeout(
  url: string,
  options: RequestInit,
  timeoutMs: number = DEFAULT_FETCH_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
}
