import { describe, it, expect, vi } from "vitest";
import { createAuthCore } from "../src/framework.js";
import type { TokenPayload } from "../src/token/types.js";

type TestCoreOptions = {
  // existing legacy test knobs used by your older tests
  roles?: string[];
  provideRoleStampProvider?: boolean;
  provideRoleVersionProvider?: boolean;
  currentRoleStamp?: string;
  currentRoleVersion?: number;

  // ✅ NEW: allow passing new adapters (like additionalClaimsProvider)
  adapterOverrides?: Record<string, any>;
  // ✅ allow any additional legacy knobs
  [key: string]: any;
};

export function makeCore(opts: TestCoreOptions = {}) {
  const roles = opts.roles ?? ["ADMIN"];
  const currentRoleStamp = opts.currentRoleStamp; //?? "etag-default";
  const currentRoleVersion = opts.currentRoleVersion; // ?? 1;

  const credentialChecker = {
    checkUserNamePassword: vi.fn(async () => ({
      ok: true as const,
      userId: "u-1",
    })),
  };

  const roleProvider = {
    getUserRoles: vi.fn(async (_userId: string) => roles),
  };

  const roleStampProvider = opts.provideRoleStampProvider
    ? { getRoleStamp: vi.fn(async (_userId: string) => currentRoleStamp) }
    : undefined;

  const roleVersionProvider = opts.provideRoleVersionProvider
    ? { getRoleVersion: vi.fn(async (_userId: string) => currentRoleVersion) }
    : undefined;

  const tokenProvider = {
    issueToken: vi.fn(async (arg1: any) => {
      // handle both possible signatures: issueToken(payload, opts) OR issueToken({payload,...})
      const payload: TokenPayload = (arg1?.payload ?? arg1) as TokenPayload;
      return `token-for-${payload.sub}`;
    }),
    verifyToken: vi.fn(async (_token: string, _opts: any) => {
      const claims: TokenPayload = {
        sub: "u-1",
        prn: "a@b.com",
        roles, // from your opts.roles
        rs: currentRoleStamp, // optional but good default when freshness enabled
        rv: currentRoleVersion, // optional
        // adx can be added if needed
      };
      return claims;
    }),
  };

  const adapters: any = {
    credentialChecker,
    roleProvider,
    ...(roleStampProvider ? { roleStampProvider } : {}),
    ...(roleVersionProvider ? { roleVersionProvider } : {}),
    tokenProvider,

    // ✅ allow override injection (additionalClaimsProvider etc.)
    ...(opts.adapterOverrides ?? {}),
  };

  console.log("opts.adapterOverrides" + JSON.stringify(opts.adapterOverrides));
  const core = createAuthCore(
    {
      issuer: "test",
      audience: ["test"],
      tokenTtlSeconds: 60,
      roleFreshness: { enabled: true },
    },
    adapters,
  );

  return {
    core,
    tokenProvider,
    roleProvider,
    roleStampProvider,
    roleVersionProvider,
    credentialChecker,
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
    const { core, tokenProvider } = makeCore({
      roles: ["ADMIN"],
      provideRoleStampProvider: true,
      provideRoleVersionProvider: true,
      currentRoleStamp: "etag-777", // what provider returns
      currentRoleVersion: 7, // what provider returns
    });

    // Token has rs that matches provider, but rv is mismatched
    (tokenProvider.verifyToken as any).mockResolvedValue({
      sub: "u-1",
      prn: "a@b.com",
      roles: ["ADMIN"],
      rs: "etag-777",
      rv: 999,
    } satisfies TokenPayload);

    const res = await core.doAuthorize({ token: "t" });

    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.userId).toBe("u-1");
      expect(res.roles).toEqual(["ADMIN"]);
      expect(res.roleStamp).toBe("etag-777");
      // roleVersion will still be returned from token (999) since you echo claims.rv
      expect(res.roleVersion).toBe(999);
    }
  });

  it("doAuthorize fails AUTH_TOKEN_STALE when roleStamp mismatches", async () => {
    const { core, tokenProvider } = makeCore({
      roles: ["USER"],
      tokenRoleStamp: "etag-old",
      currentRoleStamp: "etag-new",
      provideRoleStampProvider: true, // ✅ must exist for rs validation
    });

    // Token has rs that matches provider, but rv is mismatched
    (tokenProvider.verifyToken as any).mockResolvedValue({
      sub: "u-1",
      prn: "a@b.com",
      roles: ["ADMIN"],
      rs: "etag-777",
      rv: 999,
    } satisfies TokenPayload);

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
      currentRoleVersion: 5,
    });

    const res = await core.doAuthorize({ token: "t" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error.code).toBe("AUTH_CONFIG_ERROR");
  });

  it("doAuthorize fails with AUTH_FORBIDDEN when required roles not met", async () => {
    const { core, tokenProvider } = makeCore({
      roles: ["USER"],
      currentRoleStamp: "etag-777",
      currentRoleVersion: 999,
      provideRoleStampProvider: true,
      provideRoleVersionProvider: true,
    });

    // Token has rs that matches provider, but rv is mismatched
    (tokenProvider.verifyToken as any).mockResolvedValue({
      sub: "u-1",
      prn: "a@b.com",
      roles: ["USER"],
      rs: "etag-777",
      rv: 999,
    } satisfies TokenPayload);

    const res = await core.doAuthorize({
      token: "t",
      required: { allRoles: ["ADMIN"] },
    });

    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error.code).toBe("AUTH_FORBIDDEN");
  });

  it("doAuthorize maps token verify errors to AUTH_TOKEN_EXPIRED (heuristic)", async () => {
    const { core, tokenProvider } = makeCore({
      roles: ["USER"],
      currentRoleStamp: "etag-777",
      currentRoleVersion: 999,
      provideRoleStampProvider: true,
      provideRoleVersionProvider: true,
      verifyThrows: Object.assign(new Error("jwt expired"), {
        name: "TokenExpiredError",
      }),
    });

    tokenProvider.verifyToken = vi.fn(async (_token: string, _opts: any) => {
      throw new Error("jwt expired");
    });

    const res = await core.doAuthorize({ token: "t" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error.code).toBe("AUTH_TOKEN_EXPIRED");
  });

  it("doAuthorize fails when token missing required claims (no rs and no rv)", async () => {
    const { core, roleStampProvider, roleVersionProvider } = makeCore({
      verifiedClaims: { sub: "u-1", roles: ["USER"] } as any,
    });

    const res = await core.doAuthorize({ token: "t" });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error.code).toBe("AUTH_TOKEN_INVALID");
  });

  it("doAuthenticate includes adx in token when additionalClaimsProvider exists", async () => {
    const additionalClaimsProvider = {
      getAdditionalClaims: vi.fn(async () => ({
        tenantId: "t-101",
        displayName: "Abhinav",
        flags: { beta: true },
      })),
    };

    const { core, tokenProvider } = makeCore({
      // your helper should allow passing adapter overrides;
      // if not, just patch core creation in this test with your own createAuthCore call
      adapterOverrides: {
        additionalClaimsProvider,
      },
    } as any);

    const res = await core.doAuthenticate({
      principal: "a@b.com",
      password: "pw",
    });
    expect(res.ok).toBe(true);

    const issuedPayload = (tokenProvider.issueToken as any).mock.calls[0][0];
    console.log("issueToken.calls =", JSON.stringify(issuedPayload));
    expect(issuedPayload.adx).toEqual({
      tenantId: "t-101",
      displayName: "Abhinav",
      flags: { beta: true },
    });

    expect(additionalClaimsProvider.getAdditionalClaims).toHaveBeenCalledTimes(
      1,
    );
  });

  it("doAuthenticate does not include adx when additionalClaimsProvider is not configured", async () => {
    const { core, tokenProvider } = makeCore({} as any);

    const res = await core.doAuthenticate({
      principal: "a@b.com",
      password: "pw",
    });
    expect(res.ok).toBe(true);

    const issuedPayload = (tokenProvider.issueToken as any).mock.calls[0][0];
    expect(issuedPayload.adx).toBeUndefined();
  });

  it("doAuthenticate ignores additional claims when provider returns non-object", async () => {
    const additionalClaimsProvider = {
      getAdditionalClaims: vi.fn(async () => null as any),
    };

    const { core, tokenProvider } = makeCore({
      additionalClaimsProvider,
    } as any);

    const res = await core.doAuthenticate({
      principal: "a@b.com",
      password: "pw",
    });
    expect(res.ok).toBe(true);

    const issuedPayload = (tokenProvider.issueToken as any).mock.calls[0][0];
    expect(issuedPayload.adx).toBeUndefined();
  });
});
