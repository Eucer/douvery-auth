/**
 * @douvery/auth - PKCE Utilities
 * RFC 7636 - Proof Key for Code Exchange
 */

import type { PKCEPair } from "./types";

/** Generate a cryptographically random string for use as code_verifier */
export function generateCodeVerifier(length: number = 64): string {
  const charset =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  const randomValues = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(randomValues)
    .map((v) => charset[v % charset.length])
    .join("");
}

/** Generate a random state parameter for CSRF protection */
export function generateState(): string {
  return generateCodeVerifier(32);
}

/** Generate a random nonce for replay attack protection */
export function generateNonce(): string {
  return generateCodeVerifier(32);
}

/** Create SHA-256 hash and encode as base64url */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(hashBuffer);
}

/** Encode ArrayBuffer as base64url (RFC 4648 Section 5) */
export function base64UrlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode base64url string to ArrayBuffer */
export function base64UrlDecode(input: string): ArrayBuffer {
  let base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padding = base64.length % 4;
  if (padding) {
    base64 += "=".repeat(4 - padding);
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/** Generate a complete PKCE pair (verifier + challenge) */
export async function generatePKCEPair(): Promise<PKCEPair> {
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: "S256",
  };
}

/** Verify a code_verifier against a code_challenge */
export async function verifyCodeChallenge(
  verifier: string,
  challenge: string,
  method: "S256" | "plain" = "S256",
): Promise<boolean> {
  if (method === "plain") {
    return verifier === challenge;
  }
  const computedChallenge = await generateCodeChallenge(verifier);
  return computedChallenge === challenge;
}

/** Parse and decode a JWT token (without verification) */
export function decodeJWT<T = Record<string, unknown>>(token: string): T {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }
  const payload = parts[1];
  const decoded = base64UrlDecode(payload);
  const text = new TextDecoder().decode(decoded);
  return JSON.parse(text) as T;
}

/** Check if a JWT token is expired */
export function isTokenExpired(token: string, clockSkew: number = 60): boolean {
  try {
    const payload = decodeJWT<{ exp?: number }>(token);
    if (!payload.exp) {
      return false;
    }
    const now = Math.floor(Date.now() / 1000);
    return payload.exp < now - clockSkew;
  } catch {
    return true;
  }
}

/** Get token expiration timestamp */
export function getTokenExpiration(token: string): number | null {
  try {
    const payload = decodeJWT<{ exp?: number }>(token);
    return payload.exp ? payload.exp * 1000 : null;
  } catch {
    return null;
  }
}
