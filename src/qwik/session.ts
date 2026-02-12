/**
 * @douvery/auth/qwik - Session Adapter
 *
 * Adapts Qwik City's Cookie interface to the generic CookieAdapter
 * used by createSessionResolver().
 *
 * Memoized: returns the same adapter instance for the same Cookie object,
 * ensuring the resolver's per-request WeakMap cache works correctly when
 * multiple routeLoaders call getAccessToken() in the same SSR request.
 */

import type { CookieAdapter, CookieSetOptions } from "@douvery/auth";

/**
 * Qwik City Cookie-like interface.
 * Duck-typed to avoid hard dependency on @builder.io/qwik-city.
 */
interface QwikCookieLike {
  get(name: string): { value: string } | null;
  set(
    name: string,
    value: string | number | Record<string, unknown>,
    options?: Record<string, unknown>,
  ): void;
}

/**
 * Adapter cache ensures the SAME CookieAdapter instance is returned
 * for the same Qwik Cookie object. This is critical because:
 *
 * 1. The resolver uses WeakMap<CookieAdapter> for per-request caching
 * 2. Multiple routeLoaders in the same SSR request share the same Cookie
 * 3. Each routeLoader calls createQwikSessionAdapter(cookie)
 * 4. Without memoization, each call would create a different object
 *    → WeakMap would fail to deduplicate → duplicate network calls
 */
const adapterCache = new WeakMap<object, CookieAdapter>();

/**
 * Create a CookieAdapter from a Qwik City Cookie object.
 *
 * @example
 * ```typescript
 * import { createQwikSessionAdapter } from '@douvery/auth/qwik';
 * import { createSessionResolver } from '@douvery/auth/session';
 *
 * const resolver = createSessionResolver({ ... });
 *
 * export const useMyLoader = routeLoader$(async ({ cookie }) => {
 *   const adapter = createQwikSessionAdapter(cookie);
 *   const token = await resolver.getAccessToken(adapter);
 * });
 * ```
 */
export function createQwikSessionAdapter(
  cookie: QwikCookieLike,
): CookieAdapter {
  let adapter = adapterCache.get(cookie);
  if (adapter) return adapter;

  adapter = {
    get(name: string): string | undefined {
      return cookie.get(name)?.value ?? undefined;
    },
    set(name: string, value: string, options: CookieSetOptions): void {
      cookie.set(name, value, options as Record<string, unknown>);
    },
  };

  adapterCache.set(cookie, adapter);
  return adapter;
}
