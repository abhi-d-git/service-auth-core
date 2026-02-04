import { createAuthCore } from "../../src/framework.js";
import { JwtTokenProvider } from "../../src/token/jwtTokenProvider.js";
import type {
  CredentialChecker,
  RoleProvider,
  RoleVersionProvider,
  RoleStampProvider,
  AdditionalClaimsProvider,
} from "../../src/adapters/types.js";

// -----------------------------
// Example "DB" (in-memory)
// -----------------------------
type UserRecord = {
  userId: string;
  principal: string; // email/username
  password: string; // DEMO ONLY (use bcrypt/argon2 in real systems)
  roles: string[];
  roleVersion: number; // increment on role change
  roleStamp: string; // checksum/etag updated on role change
};

const USERS: Record<string, UserRecord> = {
  "a@b.com": {
    userId: "u-1",
    principal: "a@b.com",
    password: "pw",
    roles: ["ADMIN", "USER"],
    roleVersion: 3,
    roleStamp: "etag-3-admin-user",
  },
  "x@y.com": {
    userId: "u-2",
    principal: "x@y.com",
    password: "pw",
    roles: ["USER"],
    roleVersion: 1,
    roleStamp: "etag-1-user",
  },
};

// -----------------------------
// Service adapters
// -----------------------------
const credentialChecker: CredentialChecker = {
  async checkUserNamePassword(principal, password) {
    const u = USERS[principal];
    if (!u) return { ok: false, reason: "USER_NOT_FOUND" };
    if (u.password !== password)
      return { ok: false, reason: "INVALID_CREDENTIALS" };
    return { ok: true, userId: u.userId };
  },
};

const roleProvider: RoleProvider = {
  async getUserRoles(userId) {
    const u = Object.values(USERS).find((x) => x.userId === userId);
    return u ? u.roles : [];
  },
};

const roleVersionProvider: RoleVersionProvider = {
  async getRoleVersion(userId) {
    const u = Object.values(USERS).find((x) => x.userId === userId);
    return u ? u.roleVersion : 0;
  },
};

const roleStampProvider: RoleStampProvider = {
  async getRoleStamp(userId) {
    const u = Object.values(USERS).find((x) => x.userId === userId);
    return u ? u.roleStamp : "etag-0";
  },
};

const additionalClaimsProvider: AdditionalClaimsProvider = {
  async getAdditionalClaims(userId) {
    return {
      tenantId: "some_tenant_id for user",
    };
  },
};

// -----------------------------
// Token provider config
// Pick ONE: HS256 (dev) or RS256/EdDSA (recommended for multi-service verification)
// -----------------------------

const tokenProvider = new JwtTokenProvider({
  alg: "HS256",
  secret: "dev-secret-change-me",
  kid: "dev-k1",
});

/*
// RS256 issuer example
const tokenProvider = new JwtTokenProvider({
  alg: "RS256",
  privateKeyPem: process.env.AUTH_PRIVATE_KEY_PEM!,
  publicKeyPem: process.env.AUTH_PUBLIC_KEY_PEM!,
  kid: "rsa-k1"
});
*/
/*
// EdDSA issuer example
const tokenProvider = new JwtTokenProvider({
  alg: "EdDSA",
  privateKeyPem: process.env.AUTH_PRIVATE_KEY_PEM!,
  publicKeyPem: process.env.AUTH_PUBLIC_KEY_PEM!,
  kid: "eddsa-k1",
});
*/
// -----------------------------
// Create core + authenticate
// -----------------------------
const auth = createAuthCore(
  {
    issuer: "auth-service",
    audience: ["orders-service", "inventory-service"],
    tokenTtlSeconds: 900,
    roleFreshness: { enabled: true },
  },
  {
    credentialChecker,
    roleProvider,
    roleVersionProvider,
    roleStampProvider,
    tokenProvider,
    additionalClaimsProvider,
  } as any,
);

async function main() {
  const login = await auth.doAuthenticate({
    principal: "a@b.com",
    password: "pw",
  });

  if (!login.ok) {
    console.error("Login failed:", login.error);
    process.exit(1);
  }

  console.log("✅ Login success");
  console.log("userId:", login.userId);
  console.log("roles:", login.roles);
  console.log("roleStamp:", login.roleStamp);
  console.log("roleVersion:", login.roleVersion);
  console.log("expiresAt:", login.expiresAt);
  console.log("accessToken:", login.accessToken);
  console.log("additional info:", login.adx);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
