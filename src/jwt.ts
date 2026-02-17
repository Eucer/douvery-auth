export interface JwtClaimsBase {
  exp: number;
  sub?: string;
  sid?: string;
  aud?: string | string[];
}

function decodeBase64Url(value: string): string {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(
    normalized.length + ((4 - (normalized.length % 4)) % 4),
    "=",
  );

  if (typeof atob === "function") {
    return atob(padded);
  }

  return Buffer.from(padded, "base64").toString("utf-8");
}

export function decodeJwtClaims<TClaims extends JwtClaimsBase>(
  accessToken: string,
): TClaims {
  const parts = accessToken.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }

  const payload = decodeBase64Url(parts[1]);
  const parsed = JSON.parse(payload) as TClaims;

  if (!parsed || typeof parsed.exp !== "number") {
    throw new Error("Invalid JWT claims payload");
  }

  return parsed;
}

export function isJwtExpiredFromClaims(claims: JwtClaimsBase): boolean {
  const now = Math.floor(Date.now() / 1000);
  return claims.exp < now;
}

export function isJwtExpired(accessToken: string): boolean {
  try {
    const claims = decodeJwtClaims<JwtClaimsBase>(accessToken);
    return isJwtExpiredFromClaims(claims);
  } catch {
    return true;
  }
}

export function getJwtTimeRemaining(accessToken: string): number {
  try {
    const claims = decodeJwtClaims<JwtClaimsBase>(accessToken);
    const now = Math.floor(Date.now() / 1000);
    return Math.max(0, claims.exp - now);
  } catch {
    return 0;
  }
}

export function getJwtSubject(accessToken: string): string | null {
  try {
    const claims = decodeJwtClaims<JwtClaimsBase>(accessToken);
    return claims.sub ?? null;
  } catch {
    return null;
  }
}

export function verifyJwtAudience(
  accessToken: string,
  expectedAudience: string,
): boolean {
  try {
    const claims = decodeJwtClaims<JwtClaimsBase>(accessToken);
    const aud = claims.aud;

    if (Array.isArray(aud)) {
      return aud.includes(expectedAudience);
    }

    return aud === expectedAudience;
  } catch {
    return false;
  }
}
