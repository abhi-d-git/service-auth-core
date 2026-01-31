import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { JwtTokenProvider } from "../src/token/jwtTokenProvider.js";
import type { TokenPayload } from "../src/token/types.js";

const claimsWithRv: TokenPayload = {
  sub: "u-1",
  prn: "a@b.com",
  roles: ["ADMIN", "USER"],
  rv: 3,
};

const claimsWithRsOnly: TokenPayload = {
  sub: "u-1",
  prn: "a@b.com",
  roles: ["ADMIN", "USER"],
  rs: "etag-123",
};

describe("JwtTokenProvider (rs/rv)", () => {
  it("HS256: issue + verify (rv)", async () => {
    const tp = new JwtTokenProvider({
      alg: "HS256",
      secret: "super-secret",
      kid: "k1",
    });

    const token = await tp.issueToken(claimsWithRv, {
      issuer: "auth-service",
      audience: "mps",
      expiresInSeconds: 60,
    });

    const claims = await tp.verifyToken(token, {
      issuer: "auth-service",
      audience: "mps",
      clockSkewSeconds: 60,
    });

    expect(claims.sub).toBe("u-1");
    expect(claims.roles).toEqual(["ADMIN", "USER"]);
    expect(claims.rv).toBe(3);
    expect(claims.prn).toBe("a@b.com");
  });

  it("HS256: issue + verify (rs only)", async () => {
    const tp = new JwtTokenProvider({ alg: "HS256", secret: "super-secret" });

    const token = await tp.issueToken(claimsWithRsOnly, {
      issuer: "auth-service",
      audience: "mps",
      expiresInSeconds: 60,
    });

    const claims = await tp.verifyToken(token, {
      issuer: "auth-service",
      audience: "mps",
      clockSkewSeconds: 60,
    });

    expect(claims.sub).toBe("u-1");
    expect(claims.roles).toEqual(["ADMIN", "USER"]);
    expect(claims.rs).toBe("etag-123");
    expect(claims.rv).toBeUndefined();
  });

  it("RS256: issue with private key, verify with public key only", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    const privateKeyPem = privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString();
    const publicKeyPem = publicKey
      .export({ type: "spki", format: "pem" })
      .toString();

    const issuer = new JwtTokenProvider({
      alg: "RS256",
      privateKeyPem,
      publicKeyPem,
      kid: "rsa-1",
    });

    const verifier = new JwtTokenProvider({
      alg: "RS256",
      publicKeyPem,
      kid: "rsa-1",
    });

    const token = await issuer.issueToken(claimsWithRv, {
      issuer: "auth-service",
      audience: ["mps", "svc-a"],
      expiresInSeconds: 60,
    });

    const claims = await verifier.verifyToken(token, {
      issuer: "auth-service",
      audience: "svc-a",
      clockSkewSeconds: 60,
    });

    expect(claims.sub).toBe("u-1");
    expect(claims.roles).toEqual(["ADMIN", "USER"]);
    expect(claims.rv).toBe(3);
  });

  it("EdDSA: issue with private key, verify with public key only", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const privateKeyPem = privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString();
    const publicKeyPem = publicKey
      .export({ type: "spki", format: "pem" })
      .toString();

    const issuer = new JwtTokenProvider({
      alg: "EdDSA",
      privateKeyPem,
      publicKeyPem,
      kid: "eddsa-1",
    });

    const verifier = new JwtTokenProvider({
      alg: "EdDSA",
      publicKeyPem,
      kid: "eddsa-1",
    });

    const token = await issuer.issueToken(claimsWithRv, {
      issuer: "auth-service",
      audience: "mps",
      expiresInSeconds: 60,
    });

    const claims = await verifier.verifyToken(token, {
      issuer: "auth-service",
      audience: "mps",
      clockSkewSeconds: 60,
    });

    expect(claims.sub).toBe("u-1");
    expect(claims.roles).toEqual(["ADMIN", "USER"]);
    expect(claims.rv).toBe(3);
  });

  it("Verifier-only config cannot issue tokens (RS256)", async () => {
    const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const publicKeyPem = publicKey
      .export({ type: "spki", format: "pem" })
      .toString();

    const verifierOnly = new JwtTokenProvider({ alg: "RS256", publicKeyPem });

    await expect(
      verifierOnly.issueToken(claimsWithRv, {
        issuer: "auth-service",
        audience: "mps",
        expiresInSeconds: 60,
      }),
    ).rejects.toThrow(/privateKeyPem is required/i);
  });
});
