import { SignJWT, jwtVerify, importPKCS8, importSPKI, CryptoKey } from "jose";
import { createSecretKey } from "node:crypto";
import type {
  TokenPayload,
  TokenProvider,
  IssueTokenOptions,
  VerifyTokenOptions,
} from "./types.js";

export type JwtAlg = "HS256" | "RS256" | "EdDSA";

/**
 * Single-key config (no kid rotation map for now).
 * - HS256: secret for sign+verify
 * - RS256/EdDSA:
 *    - verify requires publicKeyPem
 *    - issue requires privateKeyPem
 */
export type JwtTokenProviderConfig =
  | {
      alg: "HS256";
      secret: string | Uint8Array;
      kid?: string;
    }
  | {
      alg: "RS256";
      publicKeyPem: string; // required to verify
      privateKeyPem?: string; // required to issue
      kid?: string;
    }
  | {
      alg: "EdDSA";
      publicKeyPem: string; // required to verify
      privateKeyPem?: string; // required to issue
      kid?: string;
    };

function toAudience(aud?: string | string[]) {
  if (!aud) return undefined;
  return Array.isArray(aud) ? aud : [aud];
}

function isNonEmptyString(x: unknown): x is string {
  return typeof x === "string" && x.trim().length > 0;
}

function ensureRequiredClaims(payload: TokenPayload) {
  if (!isNonEmptyString(payload.sub))
    throw new Error("TokenPayload.sub is required");
  if (!Array.isArray(payload.roles))
    throw new Error("TokenPayload.roles must be an array");

  const hasRv = typeof payload.rv === "number";
  const hasRs = isNonEmptyString(payload.rs);

  if (!hasRv && !hasRs) {
    throw new Error(
      "TokenPayload must have either rs (roleStamp) or rv (roleVersion)",
    );
  }
}

export class JwtTokenProvider implements TokenProvider {
  private cfg: JwtTokenProviderConfig;

  // cached keys
  private secretKey?: ReturnType<typeof createSecretKey>;
  private signingKeyPromise?: Promise<CryptoKey>;
  private verifyKeyPromise?: Promise<CryptoKey>;

  constructor(cfg: JwtTokenProviderConfig) {
    this.cfg = cfg;
  }

  private getHmacKey() {
    if (this.cfg.alg !== "HS256") throw new Error("Not HS256 config");
    if (!this.secretKey) {
      const s = this.cfg.secret;
      const bytes = typeof s === "string" ? new TextEncoder().encode(s) : s;
      this.secretKey = createSecretKey(bytes);
    }
    return this.secretKey;
  }

  private async getSigningKey(): Promise<CryptoKey> {
    if (this.cfg.alg === "HS256")
      throw new Error("HS256 does not use an asymmetric signing key");

    if (!this.cfg.privateKeyPem) {
      throw new Error(
        `${this.cfg.alg} privateKeyPem is required to issue tokens`,
      );
    }

    if (!this.signingKeyPromise) {
      this.signingKeyPromise = importPKCS8(
        this.cfg.privateKeyPem,
        this.cfg.alg,
      );
    }
    return this.signingKeyPromise;
  }

  private async getVerifyKey(): Promise<CryptoKey> {
    if (this.cfg.alg === "HS256")
      throw new Error("HS256 does not use an asymmetric verify key");

    if (!this.cfg.publicKeyPem) {
      throw new Error("publicKeyPem is required to verify tokens");
    }

    if (!this.verifyKeyPromise) {
      this.verifyKeyPromise = importSPKI(this.cfg.publicKeyPem, this.cfg.alg);
    }
    return this.verifyKeyPromise;
  }

  async issueToken(
    payload: TokenPayload,
    options: IssueTokenOptions,
  ): Promise<string> {
    ensureRequiredClaims(payload);

    const alg = this.cfg.alg;
    const kid = this.cfg.kid;

    const signer = new SignJWT(payload)
      .setProtectedHeader({ alg, ...(kid ? { kid } : {}) })
      .setIssuedAt()
      .setIssuer(options.issuer)
      .setExpirationTime(`${options.expiresInSeconds}s`);

    const aud = toAudience(options.audience);
    if (aud?.length) signer.setAudience(aud);

    if (alg === "HS256") {
      return signer.sign(this.getHmacKey());
    }

    const key = await this.getSigningKey();
    return signer.sign(key);
  }

  async verifyToken(
    token: string,
    options: VerifyTokenOptions,
  ): Promise<TokenPayload> {
    const aud = toAudience(options.audience);
    const clockTolerance = options.clockSkewSeconds ?? 60;

    if (this.cfg.alg === "HS256") {
      const { payload } = await jwtVerify(token, this.getHmacKey(), {
        issuer: options.issuer,
        audience: aud,
        clockTolerance,
      });
      return payload as TokenPayload;
    }

    const key = await this.getVerifyKey();
    const { payload } = await jwtVerify(token, key, {
      issuer: options.issuer,
      audience: aud,
      clockTolerance,
    });

    return payload as TokenPayload;
  }
}
