import type { RedirectSecurityOptions } from "./redirect";

/**
 * Allowed redirect domains for first-party Douvery properties.
 *
 * Use this to validate `continue` / `rr` params that may be absolute URLs.
 */
export const DOUVERY_ALLOWED_REDIRECT_DOMAINS: string[] = [
  "douvery.com",
  "www.douvery.com",
  "douvery.do",
  "www.douvery.do",
  "localhost",
];

export function createDouveryRedirectSecurityOptions(
  defaultRedirect: string = "/",
): RedirectSecurityOptions {
  return {
    allowedDomains: DOUVERY_ALLOWED_REDIRECT_DOMAINS,
    defaultRedirect,
  };
}
