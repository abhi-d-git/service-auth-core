import { createAuthCore } from "../../src/framework.js";
import { JwtTokenProvider } from "../../src/token/jwtTokenProvider.js";
import type {
  CredentialChecker,
  RoleProvider,
  RoleStampProvider,
  RoleVersionProvider,
} from "../../src/adapters/types.js";

// Downstream service usually doesn't check passwords.
// Dummy adapters for interface completeness:
const credentialChecker: CredentialChecker = {
  async checkUserNamePassword() {
    return { ok: false, reason: "INVALID_CREDENTIALS" };
  },
};

const roleProvider: RoleProvider = {
  async getUserRoles() {
    return [];
  },
};

// In real systems, these values would come from:
// - a local cache, or
// - a lightweight endpoint in auth-service
const roleStampProvider: RoleStampProvider = {
  async getRoleStamp(userId) {
    if (userId === "u-1") return "etag-3-admin-user";
    if (userId === "u-2") return "etag-1-user";
    return "etag-0";
  },
};

const roleVersionProvider: RoleVersionProvider = {
  async getRoleVersion(userId) {
    if (userId === "u-1") return 3;
    if (userId === "u-2") return 1;
    return 0;
  },
};

// Must match algorithm used by auth-service.
// HS256 demo uses same secret. For RS256/EdDSA use public key only.

/*
const tokenProvider = new JwtTokenProvider({
  alg: "HS256",
  secret: "dev-secret-change-me",
  kid: "dev-k1",
});
*/
/*
// RS256 verifier example
const tokenProvider = new JwtTokenProvider({
  alg: "RS256",
  publicKeyPem: process.env.AUTH_PUBLIC_KEY_PEM!,
  kid: "rsa-k1"
});
*/

// EdDSA verifier example
const tokenProvider = new JwtTokenProvider({
  alg: "EdDSA",
  publicKeyPem: process.env.AUTH_PUBLIC_KEY_PEM!,
  kid: "eddsa-k1",
});

const authz = createAuthCore(
  {
    issuer: "auth-service",
    audience: "orders-service",
    tokenTtlSeconds: 900,
    roleFreshness: { enabled: true },
  },
  {
    credentialChecker,
    roleProvider,
    roleStampProvider, // preferred freshness check
    roleVersionProvider, // fallback if token only has rv
    tokenProvider,
  } as any,
);

async function main() {
  const token = process.argv[2];
  if (!token) {
    console.error(
      'Usage: node dist-examples/orders-service/index.js "<TOKEN>"',
    );
    process.exit(1);
  }

  // Example: only ADMIN can "cancel order"
  const decision = await authz.doAuthorize({
    token,
    required: { anyRoles: ["ADMIN"] },
  });

  if (!decision.ok) {
    console.error("❌ Not authorized:", decision.error);
    process.exit(1);
  }

  console.log("✅ Authorized");
  console.log("userId:", decision.userId);
  console.log("roles:", decision.roles);
  console.log("roleStamp:", decision.roleStamp);
  console.log("roleVersion:", decision.roleVersion);

  console.log("➡️  Cancelling order ... done");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
