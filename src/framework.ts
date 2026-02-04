import type {
  AuthCore,
  AuthCoreAdapters,
  AuthCoreConfig,
  AuthenticateInput,
  AuthenticateResult,
  AuthorizeInput,
  AuthorizeResult,
} from "./types.js";
import { err } from "./errors/error.js";
import type { TokenPayload } from "./token/types.js";

function addSecondsIso(seconds: number) {
  const d = new Date();
  d.setSeconds(d.getSeconds() + seconds);
  return d.toISOString();
}

function normalizeAudience(aud?: string | string[]) {
  if (!aud) return undefined;
  return Array.isArray(aud) ? aud : [aud];
}

function isNonEmptyString(x: unknown): x is string {
  return typeof x === "string" && x.trim().length > 0;
}

function requiredMissing(claims: any): string[] {
  const missing: string[] = [];
  if (!claims || typeof claims !== "object") return ["claims"];

  if (!isNonEmptyString(claims.sub)) missing.push("sub");
  if (!Array.isArray(claims.roles)) missing.push("roles");

  const hasRs = isNonEmptyString(claims.rs);
  const hasRv = typeof claims.rv === "number";

  if (!hasRs && !hasRv) missing.push("rs|rv"); // must have at least one

  return missing;
}

function hasAllRoles(userRoles: string[], all: string[]) {
  const set = new Set(userRoles);
  return all.every((r) => set.has(r));
}

function hasAnyRole(userRoles: string[], any: string[]) {
  const set = new Set(userRoles);
  return any.some((r) => set.has(r));
}

function mapCredentialFailure(reason?: string) {
  switch (reason) {
    case "USER_LOCKED":
      return err("AUTH_USER_LOCKED", "User is locked");
    case "USER_DISABLED":
      return err("AUTH_USER_DISABLED", "User is disabled");
    default:
      return err("AUTH_INVALID_CREDENTIALS", "Invalid credentials");
  }
}

function mapTokenVerifyError(e: unknown) {
  const msg = e instanceof Error ? e.message : "Token verification failed";
  const name = e instanceof Error ? e.name : "";

  if (
    name.toLowerCase().includes("expired") ||
    msg.toLowerCase().includes("expired")
  ) {
    return err("AUTH_TOKEN_EXPIRED", "Token expired");
  }
  return err("AUTH_TOKEN_INVALID", "Token invalid", { cause: msg });
}

/**
 * Freshness check strategy:
 * - Prefer roleStamp (rs) if token has rs and roleStampProvider exists
 * - Otherwise fall back to roleVersion (rv) if token has rv and roleVersionProvider exists
 * - If freshness enabled but no compatible provider/claim -> AUTH_CONFIG_ERROR
 */
async function validateFreshness(
  userId: string,
  claims: TokenPayload,
  adapters: AuthCoreAdapters,
): Promise<{ ok: true } | { ok: false; error: ReturnType<typeof err> }> {
  const tokenRs = isNonEmptyString(claims.rs) ? claims.rs.trim() : undefined;
  const tokenRv = typeof claims.rv === "number" ? claims.rv : undefined;

  console.log(`tokenRs: ${tokenRs}  and tokenRv : ${tokenRv}`);
  console.log(
    `adapters.roleStampProvider: ${adapters.roleStampProvider}  and adapters.roleVersionProvider : ${adapters.roleVersionProvider}`,
  );
  // Prefer rs if present + provider exists
  if (tokenRs && adapters.roleStampProvider) {
    const currentRs = await adapters.roleStampProvider.getRoleStamp(userId);
    if (currentRs !== tokenRs) {
      return {
        ok: false,
        error: err(
          "AUTH_TOKEN_STALE",
          "Token is stale due to role changes (roleStamp mismatch)",
          {
            tokenRoleStamp: tokenRs,
            currentRoleStamp: currentRs,
          },
        ),
      };
    }
    return { ok: true };
  }

  // Fallback to rv if present + provider exists
  if (typeof tokenRv === "number" && adapters.roleVersionProvider) {
    const currentRv = await adapters.roleVersionProvider.getRoleVersion(userId);
    if (currentRv !== tokenRv) {
      return {
        ok: false,
        error: err(
          "AUTH_TOKEN_STALE",
          "Token is stale due to role changes (roleVersion mismatch)",
          {
            tokenRoleVersion: tokenRv,
            currentRoleVersion: currentRv,
          },
        ),
      };
    }
    return { ok: true };
  }

  // Freshness enabled but cannot validate
  return {
    ok: false,
    error: err(
      "AUTH_CONFIG_ERROR",
      "Role freshness validation is enabled but token/adapters do not support it",
      {
        hasTokenRoleStamp: Boolean(tokenRs),
        hasTokenRoleVersion: typeof tokenRv === "number",
        hasRoleStampProvider: Boolean(adapters.roleStampProvider),
        hasRoleVersionProvider: Boolean(adapters.roleVersionProvider),
      },
    ),
  };
}

export function createAuthCore(
  config: AuthCoreConfig,
  adapters: AuthCoreAdapters,
): AuthCore {
  if (!config?.issuer) throw new Error("AuthCoreConfig.issuer is required");
  if (!config?.tokenTtlSeconds || config.tokenTtlSeconds <= 0) {
    throw new Error("AuthCoreConfig.tokenTtlSeconds must be > 0");
  }

  const roleFreshnessEnabled = config.roleFreshness?.enabled ?? true;
  const clockSkewSeconds = config.clockSkewSeconds ?? 60;
  const baseAudience = normalizeAudience(config.audience);

  async function doAuthenticate(
    input: AuthenticateInput,
  ): Promise<AuthenticateResult> {
    try {
      const principal = String(input.principal ?? "").trim();
      const password = String(input.password ?? "");

      if (!principal) {
        return {
          ok: false,
          error: err("AUTH_CONFIG_ERROR", "principal is required"),
        };
      }

      const cred = await adapters.credentialChecker.checkUserNamePassword(
        principal,
        password,
      );
      if (!cred.ok)
        return { ok: false, error: mapCredentialFailure(cred.reason) };

      const userId = cred.userId;

      // Fetch roles first (needed for token)
      const roles = await adapters.roleProvider.getUserRoles(userId);

      // Fetch additional information to get added in the claim
      // src/framework.ts (inside doAuthenticate, after roles + rs/rv are known)

      let adx: Record<string, unknown> | undefined;

      if (adapters.additionalClaimsProvider) {
        const extra =
          await adapters.additionalClaimsProvider.getAdditionalClaims({
            userId,
            principal,
          });
        console.log(" payload extra: " + extra);
        // Accept only plain objects; ignore null/arrays for safety
        if (extra && typeof extra === "object" && !Array.isArray(extra)) {
          // optionally drop empty object
          if (Object.keys(extra).length > 0) adx = extra;
        }
      }
      console.log(
        " adapters.additionalClaimsProvider: " +
          adapters.additionalClaimsProvider,
      );

      // Fetch rs/rv if providers exist (both are optional; include what we can)
      const [roleStamp, roleVersion] = await Promise.all([
        adapters.roleStampProvider
          ? adapters.roleStampProvider.getRoleStamp(userId)
          : Promise.resolve(undefined),
        adapters.roleVersionProvider
          ? adapters.roleVersionProvider.getRoleVersion(userId)
          : Promise.resolve(undefined),
      ]);

      const payload: TokenPayload = { sub: userId, prn: principal, roles };

      if (isNonEmptyString(roleStamp)) payload.rs = roleStamp;
      if (typeof roleVersion === "number") payload.rv = roleVersion;
      if (adx && Object.keys(adx).length > 0) payload.adx = adx;
      console.log(" payload adx: " + payload.adx);
      console.log(" payload adx-adx: " + adx);

      // Note: JwtTokenProvider requires at least one of rs/rv.
      // If a service doesn't provide either, token issuance will fail (good safety default).
      const accessToken = await adapters.tokenProvider.issueToken(payload, {
        issuer: config.issuer,
        audience: baseAudience,
        expiresInSeconds: config.tokenTtlSeconds,
      });

      return {
        ok: true,
        accessToken,
        expiresAt: addSecondsIso(config.tokenTtlSeconds),
        userId,
        roles,
        ...(payload.rs ? { roleStamp: payload.rs } : {}),
        ...(typeof payload.rv === "number" ? { roleVersion: payload.rv } : {}),
        ...(adx ? { adx } : {}),
      };
    } catch (e) {
      return {
        ok: false,
        error: err("AUTH_INTERNAL_ERROR", "Internal error", {
          cause: String(e),
        }),
      };
    }
  }

  async function doAuthorize(input: AuthorizeInput): Promise<AuthorizeResult> {
    try {
      const expectedAudience =
        normalizeAudience(input.expectedAudience) ?? baseAudience;

      let claims: TokenPayload;
      try {
        claims = await adapters.tokenProvider.verifyToken(input.token, {
          issuer: config.issuer,
          audience: expectedAudience,
          clockSkewSeconds,
        });
        console.log("claims : " + JSON.stringify(claims));
      } catch (e) {
        return { ok: false, error: mapTokenVerifyError(e) };
      }

      const missing = requiredMissing(claims);
      console.log("missing : " + missing);
      if (missing.length > 0) {
        return {
          ok: false,
          error: err("AUTH_TOKEN_INVALID", "Token missing required claims", {
            missing,
          }),
        };
      }

      const userId = claims.sub;
      const roles = claims.roles as string[];
      const adx = claims.adx;

      // Freshness validation (rs preferred, rv fallback)
      if (roleFreshnessEnabled) {
        const freshness = await validateFreshness(userId, claims, adapters);
        console.log("freshness : " + JSON.stringify(freshness));
        if (!freshness.ok) return { ok: false, error: freshness.error };
      }

      // Role policy checks
      const reqAny = input.required?.anyRoles ?? [];
      const reqAll = input.required?.allRoles ?? [];
      console.log("reqAny : " + reqAny);
      console.log("reqAll : " + reqAll);
      if (reqAll.length > 0 && !hasAllRoles(roles, reqAll)) {
        return {
          ok: false,
          error: err("AUTH_FORBIDDEN", "Missing required roles (allRoles)", {
            requiredAll: reqAll,
            actual: roles,
          }),
        };
      }

      if (reqAny.length > 0 && !hasAnyRole(roles, reqAny)) {
        return {
          ok: false,
          error: err("AUTH_FORBIDDEN", "Missing required roles (anyRoles)", {
            requiredAny: reqAny,
            actual: roles,
          }),
        };
      }

      return {
        ok: true,
        userId,
        roles,
        ...(isNonEmptyString(claims.rs) ? { roleStamp: claims.rs } : {}),
        ...(typeof claims.rv === "number" ? { roleVersion: claims.rv } : {}),
        principal: isNonEmptyString(claims.prn) ? claims.prn : undefined,
        claims,
        ...adx,
      };
    } catch (e) {
      console.log("Exception : " + e);
      return {
        ok: false,
        error: err("AUTH_INTERNAL_ERROR", "Internal error", {
          cause: String(e),
        }),
      };
    }
  }

  return { doAuthenticate, doAuthorize };
}
