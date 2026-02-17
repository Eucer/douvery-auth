import { sanitizeRedirectUrl, type RedirectSecurityOptions } from "./security";

// =============================================================================
// New API (SDK-level naming)
// =============================================================================

export type AuthBaseOptions = {
  /** Base URL of the Auth app (e.g. https://auth.douvery.com). */
  authBaseUrl: string;
  /** Redirect validation options. If omitted, defaults to a strict policy. */
  redirectSecurity?: RedirectSecurityOptions;
};

export type LoginUrlOptions = AuthBaseOptions & {
  /** Where to redirect after login. */
  returnTo?: string;
  /** Query param name used by the auth app. Defaults to `continue`. */
  returnParam?: "continue" | "rr";
  /** Pass `prompt=select_account` to open the account chooser UI. */
  prompt?: "select_account";
  /** When true: login page will keep current session as secondary and allow adding a new account. */
  addAccount?: boolean;
  /** Prefill email field. */
  email?: string;
};

export type SelectAccountUrlOptions = AuthBaseOptions & {
  /** Where to redirect after selecting the account. */
  returnTo?: string;
};

export type LogoutUrlOptions = AuthBaseOptions & {
  /** Where to redirect after logout. */
  returnTo?: string;
};

export type VerifyAccountUrlOptions = AuthBaseOptions & {
  /** Where to redirect after account verification. */
  returnTo?: string;
  /** Query param name used by the auth app. Defaults to `continue`. */
  returnParam?: "continue" | "rr";
};

export type UpgradeAccountUrlOptions = AuthBaseOptions & {
  /** Where to redirect after upgrading the account. */
  returnTo?: string;
  /** Query param name used by the auth app. Defaults to `continue`. */
  returnParam?: "continue" | "rr";
};

export type AuthUrlOptions = AuthBaseOptions & {
  /** Path in the auth app (e.g. "/login", "/verify-account"). */
  path: string;
  /** Where to redirect after completing the flow. */
  returnTo?: string;
  /** Query param name used by the auth app. Defaults to `continue`. */
  returnParam?: "continue" | "rr";
};

function normalizeOrigin(value: string): string {
  return (value || "").trim().replace(/\/+$/, "");
}

function withLeadingSlash(value: string): string {
  const trimmed = (value || "").trim();
  if (!trimmed) return "/";
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}

function joinUrl(origin: string, path: string): string {
  const o = normalizeOrigin(origin);
  const p = withLeadingSlash(path).replace(/\/+$/, "");
  return o ? `${o}${p}` : p;
}

function canUseWindowOrigin(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.location?.origin === "string" &&
    !!window.location.origin
  );
}

function normalizeReturnUrlForRuntime(rawUrl: string): string {
  const trimmed = (rawUrl || "").trim();
  if (!trimmed) return "/";

  // Already absolute.
  if (/^https?:\/\//i.test(trimmed)) return trimmed;

  // Upgrade relative → absolute in the browser.
  if (
    trimmed.startsWith("/") &&
    !trimmed.startsWith("//") &&
    canUseWindowOrigin()
  ) {
    return new URL(trimmed, window.location.origin).toString();
  }

  return trimmed;
}

function getDefaultRedirectSecurity(): RedirectSecurityOptions {
  // By default we allow:
  // - relative URLs (always)
  // - absolute URLs ONLY when they point back to the current browser hostname
  //   (so consumers can safely pass "/" and still get an absolute continueUrl).
  if (typeof window !== "undefined" && window.location?.hostname) {
    return {
      allowedDomains: [window.location.hostname],
      defaultRedirect: "/",
    };
  }

  // Safe default for server/runtime without window: only relative URLs.
  return { allowedDomains: [], defaultRedirect: "/" };
}

function createUrlOrThrow(raw: string): URL {
  try {
    return new URL(raw);
  } catch {
    throw new Error(
      "Invalid authBaseUrl/authWebBaseUrl: must be an absolute URL",
    );
  }
}

function applyReturnToParam(options: {
  url: URL;
  redirectSecurity: RedirectSecurityOptions;
  param: string;
  returnTo?: string;
}): void {
  if (!options.returnTo) return;
  const normalized = normalizeReturnUrlForRuntime(options.returnTo);
  const safe = sanitizeRedirectUrl(normalized, options.redirectSecurity);
  options.url.searchParams.set(options.param, safe);
}

function createAuthAppUrl(options: AuthUrlOptions): URL {
  const {
    authBaseUrl,
    redirectSecurity = getDefaultRedirectSecurity(),
    path,
    returnTo,
    returnParam = "continue",
  } = options;

  const url = createUrlOrThrow(joinUrl(authBaseUrl, path));

  applyReturnToParam({
    url,
    redirectSecurity,
    param: returnParam,
    returnTo,
  });

  return url;
}

/**
 * Build Auth URL for an arbitrary path in the Auth app.
 */
export function createAuthUrl(options: AuthUrlOptions): string {
  return createAuthAppUrl(options).toString();
}

/**
 * Build Auth URL: /login
 */
export function createLoginUrl(options: LoginUrlOptions): string {
  const {
    authBaseUrl,
    redirectSecurity = getDefaultRedirectSecurity(),
    returnTo,
    returnParam = "continue",
    prompt,
    addAccount,
    email,
  } = options;

  const url = createAuthAppUrl({
    authBaseUrl,
    redirectSecurity,
    path: "/login",
    returnTo,
    returnParam,
  });

  if (prompt) {
    url.searchParams.set("prompt", prompt);
  }

  if (addAccount) {
    url.searchParams.set("add_account", "true");
  }

  if (email) {
    url.searchParams.set("email", email);
  }

  return url.toString();
}

/**
 * Build Auth URL: /select-account
 */
export function createSelectAccountUrl(
  options: SelectAccountUrlOptions,
): string {
  const {
    authBaseUrl,
    redirectSecurity = getDefaultRedirectSecurity(),
    returnTo,
  } = options;

  const url = createAuthAppUrl({
    authBaseUrl,
    redirectSecurity,
    path: "/select-account",
    returnTo,
    returnParam: "continue",
  });

  return url.toString();
}

/**
 * Build Auth URL: GET /api/logout
 *
 * This is intended for top-level navigation (no CORS). It clears the shared
 * session cookie and redirects back using the `rr` query param.
 */
export function createLogoutUrl(options: LogoutUrlOptions): string {
  const {
    authBaseUrl,
    redirectSecurity = getDefaultRedirectSecurity(),
    returnTo,
  } = options;

  const url = createAuthAppUrl({
    authBaseUrl,
    redirectSecurity,
    path: "/api/logout",
    returnTo,
    returnParam: "rr",
  });

  return url.toString();
}

/**
 * Build Auth URL: /verify-account
 */
export function createVerifyAccountUrl(
  options: VerifyAccountUrlOptions,
): string {
  const {
    authBaseUrl,
    redirectSecurity = getDefaultRedirectSecurity(),
    returnTo,
    returnParam = "continue",
  } = options;

  const url = createAuthAppUrl({
    authBaseUrl,
    redirectSecurity,
    path: "/verify-account",
    returnTo,
    returnParam,
  });

  return url.toString();
}

/**
 * Build Auth URL: /upgrade-account
 */
export function createUpgradeAccountUrl(
  options: UpgradeAccountUrlOptions,
): string {
  const {
    authBaseUrl,
    redirectSecurity = getDefaultRedirectSecurity(),
    returnTo,
    returnParam = "continue",
  } = options;

  const url = createAuthAppUrl({
    authBaseUrl,
    redirectSecurity,
    path: "/upgrade-account",
    returnTo,
    returnParam,
  });

  return url.toString();
}
