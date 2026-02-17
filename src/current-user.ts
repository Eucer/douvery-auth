import { decodeJwtClaims, isJwtExpiredFromClaims } from "./jwt";
import type { JwtClaimsBase } from "./jwt";

export interface CreateCurrentUserResolverOptions<
  TClaims extends JwtClaimsBase,
  TUserInfo,
  TCurrentUser,
> {
  fetchUserInfo: (
    accessToken: string,
    claims: TClaims,
    sessionIdFromCookie?: string,
  ) => Promise<TUserInfo>;
  buildCurrentUser: (
    claims: TClaims,
    userInfo: TUserInfo,
    accessToken: string,
  ) => TCurrentUser;
  decodeAccessToken?: (accessToken: string) => TClaims;
  isDev?: boolean;
  onExpiredTokenDetected?: (claims: TClaims) => void;
}

export interface CurrentUserResolver<TClaims, TCurrentUser> {
  decodeAccessToken: (accessToken: string) => TClaims;
  getCurrentUser: (
    accessToken: string,
    options?: { sessionId?: string },
  ) => Promise<TCurrentUser>;
}

export function createCurrentUserResolver<
  TClaims extends JwtClaimsBase,
  TUserInfo,
  TCurrentUser,
>(
  options: CreateCurrentUserResolverOptions<TClaims, TUserInfo, TCurrentUser>,
): CurrentUserResolver<TClaims, TCurrentUser> {
  const loggedExpiredTokenKeys = new Set<string>();

  const decode =
    options.decodeAccessToken ??
    ((accessToken: string) => decodeJwtClaims<TClaims>(accessToken));

  async function getCurrentUser(
    accessToken: string,
    runtimeOptions?: { sessionId?: string },
  ): Promise<TCurrentUser> {
    const claims = decode(accessToken);

    if (options.isDev && isJwtExpiredFromClaims(claims)) {
      const tokenKey = `${claims.sub || "no-sub"}:${claims.sid || "no-sid"}:${claims.exp}`;
      if (!loggedExpiredTokenKeys.has(tokenKey)) {
        loggedExpiredTokenKeys.add(tokenKey);
        options.onExpiredTokenDetected?.(claims);
      }
    }

    const userInfo = await options.fetchUserInfo(
      accessToken,
      claims,
      runtimeOptions?.sessionId,
    );

    return options.buildCurrentUser(claims, userInfo, accessToken);
  }

  return {
    decodeAccessToken: decode,
    getCurrentUser,
  };
}
