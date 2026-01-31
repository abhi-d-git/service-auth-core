# service-auth-core

A **service-agnostic, pluggable authentication & authorization core** for microservices.

`service-auth-core` provides a clean, framework-independent way to implement:

- Authentication (username/password → token)
- Authorization (token → role checks)
- JWT issuing & verification (HS256 / RS256 / EdDSA)
- Role freshness validation using **roleVersion**
- Multi-service token verification (public-key based)

It deliberately avoids coupling to:

- Express / Fastify / NestJS
- Any database or ORM
- Any specific identity store

Instead, services plug in their own adapters.

---

## Why this library?

Most systems end up with:

- auth logic duplicated across services
- inconsistent role checks
- tightly coupled frameworks or DB assumptions

`service-auth-core` solves this by:

- defining a **clear contract**
- centralizing authn/authz logic
- keeping services in control of storage and frameworks

---

## Core concepts

### Authentication

principal + password  
→ service-auth-core  
→ JWT (roles + roleVersion)

### Authorization

JWT  
→ verify signature + expiry  
→ validate roleVersion  
→ check required roles  
→ allow / deny

---

## Installation

```bash
npm install service-auth-core
```

---

## High-level API

```ts
import { createAuthCore } from "service-auth-core";

const auth = createAuthCore(config, adapters);

auth.doAuthenticate(...)
auth.doAuthorize(...)
```

---

## Public API

### createAuthCore(config, adapters)

Creates an auth core instance.

```ts
function createAuthCore(
  config: AuthCoreConfig,
  adapters: AuthCoreAdapters,
): AuthCore;
```

---

### doAuthenticate()

Authenticates a user and issues a token.

```ts
const result = await auth.doAuthenticate({
  principal: "user@example.com",
  password: "secret",
});
```

Success:

```ts
{
  ok: true,
  accessToken: string,
  expiresAt: string,
  userId: string,
  roles: string[],
  roleVersion: number
}
```

Failure:

```ts
{
  ok: false,
  error: { code, message }
}
```

---

### doAuthorize()

Verifies a token and enforces role-based authorization.

```ts
const result = await auth.doAuthorize({
  token,
  required: { anyRoles: ["ADMIN"] },
});
```

Success:

```ts
{
  ok: true,
  userId,
  roles,
  roleVersion,
  principal?,
  claims
}
```

Failure:

```ts
{
  ok: false,
  error: { code, message }
}
```

---

## Configuration

### AuthCoreConfig

```ts
type AuthCoreConfig = {
  issuer: string;
  audience?: string | string[];
  tokenTtlSeconds: number;

  roleFreshness?: {
    enabled: boolean; // default: true
  };

  clockSkewSeconds?: number; // default: 60
};
```

---

## Adapters (implemented by services)

### CredentialChecker

Validates principal + password (hash comparison, lock checks, etc).

```ts
checkUserNamePassword(principal: string, password: string)
```

---

### RoleProvider

Returns all roles associated with a user.

```ts
getUserRoles(userId: string): Promise<string[]>
```

---

### RoleVersionProvider

Returns a version that changes whenever roles change.

```ts
getRoleVersion(userId: string): Promise<number>
```

---

### TokenProvider

Abstracts JWT signing and verification.

Default implementation: `JwtTokenProvider`.

---

## Token payload (JWT claims)

```ts
{
  sub: string;     // userId
  prn?: string;   // principal (email/username)
  roles: string[];
  rv: number;     // roleVersion
}
```

---

## Default TokenProvider (JWT)

Supports:

- HS256
- RS256
- EdDSA (Ed25519)

---

## Key Management

### Recommended choice for microservices

Use **asymmetric algorithms**:

- RS256 (widely supported)
- EdDSA (Ed25519 – modern, fast)

Only the Auth service holds the private key.  
Downstream services verify using the public key.

---

### HS256 (shared secret – dev only)

```ts
const tokenProvider = new JwtTokenProvider({
  alg: "HS256",
  secret: process.env.AUTH_SECRET!,
});
```

---

### RS256

Auth service:

```ts
const tokenProvider = new JwtTokenProvider({
  alg: "RS256",
  privateKeyPem: process.env.AUTH_PRIVATE_KEY_PEM!,
  publicKeyPem: process.env.AUTH_PUBLIC_KEY_PEM!,
  kid: "rsa-k1",
});
```

Downstream service:

```ts
const tokenProvider = new JwtTokenProvider({
  alg: "RS256",
  publicKeyPem: process.env.AUTH_PUBLIC_KEY_PEM!,
});
```

---

### EdDSA (Ed25519)

Auth service:

```ts
const tokenProvider = new JwtTokenProvider({
  alg: "EdDSA",
  privateKeyPem: process.env.AUTH_PRIVATE_KEY_PEM!,
  publicKeyPem: process.env.AUTH_PUBLIC_KEY_PEM!,
  kid: "eddsa-k1",
});
```

Downstream service:

```ts
const tokenProvider = new JwtTokenProvider({
  alg: "EdDSA",
  publicKeyPem: process.env.AUTH_PUBLIC_KEY_PEM!,
});
```

---

## Generating keys

### RSA

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_private.pem
openssl pkey -in rsa_private.pem -pubout -out rsa_public.pem
```

### Ed25519

```bash
openssl genpkey -algorithm ed25519 -out ed_private.pem
openssl pkey -in ed_private.pem -pubout -out ed_public.pem
```

---

## RoleVersion (why it matters)

RoleVersion prevents stale tokens after role changes.

- Token embeds roleVersion (rv)
- On authorize, current roleVersion is rechecked
- Mismatch → AUTH_TOKEN_STALE

This enables stateless tokens with controlled invalidation.

---

## Error codes

- AUTH_INVALID_CREDENTIALS
- AUTH_USER_LOCKED
- AUTH_USER_DISABLED
- AUTH_TOKEN_INVALID
- AUTH_TOKEN_EXPIRED
- AUTH_TOKEN_STALE
- AUTH_FORBIDDEN
- AUTH_CONFIG_ERROR
- AUTH_INTERNAL_ERROR

---

## Design principles

- No framework lock-in
- No DB assumptions
- Explicit contracts
- Easy to test
- Safe defaults

---

## Roadmap

- Multiple public keys via kid (rotation)
- JWKS support
- Permissions / policy engine
- Refresh tokens
- Multi-tenant helpers

---

## License

MIT
