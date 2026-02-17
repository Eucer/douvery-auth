export interface RedirectSecurityOptions {
  allowedDomains: string[];
  defaultRedirect?: string;
}

export const DEFAULT_DANGEROUS_REDIRECT_PATTERNS: RegExp[] = [
  /javascript:/i,
  /data:/i,
  /vbscript:/i,
  /<script/i,
  /%3cscript/i,
  /\0/,
  /[\r\n]/,
];

export function containsDangerousRedirectCharacters(url: string): boolean {
  return DEFAULT_DANGEROUS_REDIRECT_PATTERNS.some((pattern) =>
    pattern.test(url),
  );
}

export function isAllowedRedirectUrl(
  url: string,
  allowedDomains: string[],
): boolean {
  if (!url || typeof url !== "string") return false;

  const trimmedUrl = url.trim();

  if (trimmedUrl.startsWith("/") && !trimmedUrl.startsWith("//")) {
    return !containsDangerousRedirectCharacters(trimmedUrl);
  }

  if (trimmedUrl.startsWith("//")) {
    return false;
  }

  try {
    const parsedUrl = new URL(trimmedUrl);
    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      return false;
    }

    const hostname = parsedUrl.hostname.toLowerCase();
    return allowedDomains.some(
      (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
    );
  } catch {
    return false;
  }
}

export function sanitizeRedirectUrl(
  url: string | null | undefined,
  options: RedirectSecurityOptions,
): string {
  const defaultRedirect = options.defaultRedirect ?? "/";

  if (!url) return defaultRedirect;

  let decodedUrl = url;
  try {
    decodedUrl = decodeURIComponent(url);
  } catch {
    // Keep original value when URL is malformed
  }

  if (isAllowedRedirectUrl(decodedUrl, options.allowedDomains)) {
    return decodedUrl;
  }

  return defaultRedirect;
}

export function buildSafeRedirectUrl(
  basePath: string,
  returnUrl: string,
  options: RedirectSecurityOptions,
): string {
  const safeReturnUrl = sanitizeRedirectUrl(returnUrl, options);
  return `${basePath}?rr=${encodeURIComponent(safeReturnUrl)}`;
}

export function extractRedirectParam(
  url: URL | string,
  options: RedirectSecurityOptions,
): string {
  try {
    const urlObject = typeof url === "string" ? new URL(url) : url;
    const redirectParam = urlObject.searchParams.get("rr");
    return sanitizeRedirectUrl(redirectParam, options);
  } catch {
    return options.defaultRedirect ?? "/";
  }
}
