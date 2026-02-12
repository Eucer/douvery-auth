/**
 * @douvery/auth/session - Opaque Session Resolution
 *
 * Framework-agnostic session_id -> JWT resolution layer.
 * Use createSessionResolver() to create a resolver instance,
 * then pass a CookieAdapter to interact with your framework's cookie API.
 *
 * @example
 * ```typescript
 * import { createSessionResolver } from '@douvery/auth/session';
 *
 * const resolver = createSessionResolver({
 *   sessionApiUrl: 'http://localhost:9924/api/session',
 *   cookieName: 'my-session',
 *   internalServiceName: 'auth-web',
 *   internalServiceSecret: process.env.INTERNAL_SERVICE_SECRET,
 *   debug: process.env.NODE_ENV === 'development',
 * });
 *
 * // In a request handler (with your framework's cookie adapter):
 * const token = await resolver.getAccessToken(cookieAdapter);
 * ```
 */

// Factory
export { createSessionResolver } from "./resolver";

// Types
export type {
  SessionResolverConfig,
  CookieAdapter,
  CookieSetOptions,
  RefreshResult,
  SessionLogger,
  SessionResolver,
} from "./types";

// Utilities (for advanced usage / custom resolvers)
export { parseJwtExp, computeCacheTTL, fetchWithTimeout } from "./utils";
