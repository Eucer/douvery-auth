/**
 * @douvery/auth - Session Utilities
 */

/** Default fetch timeout: 3 seconds */
const DEFAULT_FETCH_TIMEOUT_MS = 3_000;

const DEFINITIVE_SESSION_FAILURE_SIGNALS = [
  "invalid_session",
  "session_not_found",
  "session not found",
  "session_expired",
  "session expired",
  "revoked",
  "no session",
] as const;

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

/**
 * Returns true only when the response represents a definitive invalid/expired session.
 * Use this before clearing HttpOnly session cookies.
 */
export function hasDefinitiveSessionFailure(
  status: number,
  errorText: string,
): boolean {
  if (status !== 401 && status !== 404) return false;
  const normalizedError = errorText.toLowerCase();
  return DEFINITIVE_SESSION_FAILURE_SIGNALS.some((signal) =>
    normalizedError.includes(signal),
  );
}
