import { describe, it, expect, vi } from "vitest";
import { createAuthCore } from "../src/framework.js";
import type { TokenPayload } from "../src/token/types.js";

function makeCore(
  mocks?: Partial<{
    credOk: boolean;
    credReason: any;

    roles: string[];

    // token-side claims
    tokenRoleVersion?: number;
    tokenRoleStamp?: string;

    // current values (provider-side)
    currentRoleVersion?: number;
    currentRoleStamp?: string;

    // toggle whether providers exist
    provideRoleVersionProvider?: boolean;
    provideRoleStampProvider?: boolean;

    verifyThrows: Error;
    verifiedClaims: TokenPayload;
  }>,
) {
  const credOk = mocks?.credOk ?? true;
  const roles = mocks?.roles ?? ["USER"];

  const provideRoleVersionProvider = mocks?.provideRoleVersionProvider ?? true;
  const provideRoleStampProvider = mocks?.provideRoleStampProvider ?? true;

  const tokenRoleVersion = mocks?.tokenRoleVersion;
  const tokenRoleStamp = mocks?.tokenRoleStamp;

  const currentRoleVersion =
    mocks?.currentRoleVersion ??
    (typeof tokenRoleVersion === "number" ? tokenRoleVersion : 1);

  const currentRoleStamp =
    mocks?.currentRoleStamp ?? tokenRoleStamp ?? "stamp-1";

  const credentialChecker = {
    checkUserNamePassword: vi.fn(
      async (_principal: string, _password: string) => {
        if (credOk) return { ok: true as const, userId: "u-1" };
        return { ok: false as const, reason: mocks?.credReason };
      },
    ),
  };

  const roleProvider = {
    getUserRoles: vi.fn(async (_userId: string) => roles),
  };

  const roleVersionProvider = provideRoleVersionProvider
    ? {
        getRoleVersion: vi.fn(async (_userId: string) => currentRoleVersion),
      }
    : undefined;

  const roleStampProvider = provideRoleStampProvider
    ? {
        getRoleStamp: vi.fn(async (_userId: string) => currentRoleStamp),
      }
    : undefined;

  const tokenProvider = {
    issueToken: vi.fn(
      async (payload: TokenPayload) => `token-for-${payload.sub}`,
    ),
    verifyToken: vi.fn(async (_token: string) => {
      if (mocks?.verifyThrows) throw mocks.verifyThrows;

      // default verified claims:
      // include rs if provided; include rv if provided; if neither provided, include rv=1 to satisfy required claims
      const base: TokenPayload = {
        sub: "u-1",
        prn: "a@b.com",
        roles,
      };

      if (typeof tokenRoleVersion === "number") base.rv = tokenRoleVersion;
      if (typeof tokenRoleStamp === "string") base.rs = tokenRoleStamp;

      if (base.rs === undefined && base.rv === undefined) base.rv = 1;

      return mocks?.verifiedClaims ?? base;
    }),
  };

  const core = createAuthCore(
    {
      issuer: "auth-service",
      audience: "mps",
      tokenTtlSeconds: 900,
      roleFreshness: { enabled: true },
      clockSkewSeconds: 60,
    },
    {
      credentialChecker,
      roleProvider,
      roleVersionProvider,
      roleStampProvider,
      tokenProvider,
    } as any,
  );

  return {
    core,
    credentialChecker,
    roleProvider,
    roleVersionProvider,
    roleStampProvider,
    tokenProvider,
  };
}

describe("service-auth-core (roleStamp + roleVersion)", () => {
  it("doAuthenticate issues token including rs and rv when providers exist", async () => {
    const {
      core,
      tokenProvider,
      roleProvider,
      roleVersionProvider,
      roleStampProvider,
    } = makeCore({
      roles: ["ADMIN", "USER"],
      provideRoleVersionProvider: true,
      provideRoleStampProvider: true,
      currentRoleVersion: 7,
      currentRoleStamp: "etag-777",
    });

    const res = await core.doAuthenticate({
      principal: "a@b.com",
      password: "pw",
    });

    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.userId).toBe("u-1");
      expect(res.roles).toEqual(["ADMIN", "USER"]);
      expect(res.roleVersion).toBe(7);
      expect(res.roleStamp).toBe("etag-777");
      expect(res.accessToken).toBe("token-for-u-1");
    }

    expect(roleProvider.getUserRoles).toHaveBeenCalledWith("u-1");
    expect(roleVersionProvider!.getRoleVersion).toHaveBeenCalledWith("u-1");
    expect(roleStampProvider!.getRoleStamp).toHaveBeenCalledWith("u-1");

    const issuedPayload = (tokenProvider.issueToken as any).mock
      .calls[0][0] as TokenPayload;
    expect(issuedPayload.sub).toBe("u-1");
    expect(issuedPayload.roles).toEqual(["ADMIN", "USER"]);
    expect(issuedPayload.rv).toBe(7);
    expect(issuedPayload.rs).toBe("etag-777");
    expect(issuedPayload.prn).toBe("a@b.com");
  });

  it("doAuthorize prefers roleStamp (rs) when present", async () => {
    const { core, roleStampProvider, roleVersionProvider } = makeCore({
      roles: ["ADMIN", "USER"],
      tokenRoleStamp: "etag-1",
      tokenRoleVersion: 123, // even if present, rs should be used first
      currentRoleStamp: "etag-1",
      currentRoleVersion: 999,
    });

    const res = await core.doAuthorize({
      token: "t",
      required: { anyRoles: ["ADMIN"] },
    });

    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.userId).toBe("u-1");
      expect(res.roleStamp).toBe("etag-1");
      expect(res.roleVersion).toBe(123);
    }

    expect(roleStampProvider!.getRoleStamp).toHaveBeenCalledWith("u-1");
    // roleVersionProvider should NOT be needed when rs matches
    expect(roleVersionProvider!.getRoleVersion).not.toHaveBeenCalled();
  });

  it("doAuthorize fails AUTH_TOKEN_STALE when roleStamp mismatches", async () => {
    const { core } = makeCore({
      roles: ["USER"],
      tokenRoleStamp: "etag-old",
      currentRoleStamp: "etag-new",
    });

    const res = await core.doAuthorize({ token: "t" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error.code).toBe("AUTH_TOKEN_STALE");
  });

  it("doAuthorize falls back to roleVersion when rs is absent", async () => {
    const { core, roleVersionProvider } = makeCore({
      roles: ["USER"],
      tokenRoleVersion: 5,
      provideRoleStampProvider: false,
      provideRoleVersionProvider: true,
      currentRoleVersion: 5,
    });

    const res = await core.doAuthorize({ token: "t" });
    expect(res.ok).toBe(true);

    expect(roleVersionProvider!.getRoleVersion).toHaveBeenCalledWith("u-1");
  });

  it("doAuthorize returns AUTH_CONFIG_ERROR if freshness enabled but cannot validate", async () => {
    const { core } = makeCore({
      // token has only rs, but provider missing
      tokenRoleStamp: "etag-1",
      provideRoleStampProvider: false,
      provideRoleVersionProvider: false,
    });

    const res = await core.doAuthorize({ token: "t" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error.code).toBe("AUTH_CONFIG_ERROR");
  });

  it("doAuthorize fails with AUTH_FORBIDDEN when required roles not met", async () => {
    const { core } = makeCore({
      roles: ["USER"],
      tokenRoleStamp: "etag-1",
      currentRoleStamp: "etag-1",
    });

    const res = await core.doAuthorize({
      token: "t",
      required: { allRoles: ["ADMIN"] },
    });

    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error.code).toBe("AUTH_FORBIDDEN");
  });

  it("doAuthorize maps token verify errors to AUTH_TOKEN_EXPIRED (heuristic)", async () => {
    const { core } = makeCore({
      verifyThrows: Object.assign(new Error("jwt expired"), {
        name: "TokenExpiredError",
      }),
    });

    const res = await core.doAuthorize({ token: "t" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error.code).toBe("AUTH_TOKEN_EXPIRED");
  });

  it("doAuthorize fails when token missing required claims (no rs and no rv)", async () => {
    const { core } = makeCore({
      verifiedClaims: { sub: "u-1", roles: ["USER"] } as any,
    });

    const res = await core.doAuthorize({ token: "t" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error.code).toBe("AUTH_TOKEN_INVALID");
  });
});
