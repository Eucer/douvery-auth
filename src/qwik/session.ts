/**
 * @douvery/auth/qwik - Session Adapter
 *
 * Adapts Qwik City's Cookie interface to the generic CookieAdapter
 * used by createSessionService().
 *
 * Memoized: returns the same adapter instance for the same Cookie object,
 * ensuring a stable adapter identity when multiple routeLoaders share
 * the same Cookie object in the same SSR request.
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
 * 1. Session utilities can use adapter identity for request-scoped logic
 * 2. Multiple routeLoaders in the same SSR request share the same Cookie
 * 3. Each routeLoader calls createQwikSessionAdapter(cookie)
 * 4. Without memoization, each call would create a different adapter object
 */
const adapterCache = new WeakMap<object, CookieAdapter>();

/**
 * Create a CookieAdapter from a Qwik City Cookie object.
 *
 * @example
 * ```typescript
 * import { createQwikSessionAdapter } from '@douvery/auth/qwik';
 * import { createSessionService } from '@douvery/auth/session';
 *
 * const service = createSessionService({ ... });
 *
 * export const useMyLoader = routeLoader$(async ({ cookie }) => {
 *   const adapter = createQwikSessionAdapter(cookie);
 *   const session = await service.getSession(adapter);
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
