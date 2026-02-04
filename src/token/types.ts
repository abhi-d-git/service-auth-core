export type TokenPayload = {
  sub: string; // userId
  prn?: string; // principal
  roles: string[];
  rs?: string; // roleStamp (preferred)
  rv?: number; // roleVersion (legacy/optional)
  adx?: Record<string, unknown>;
  [key: string]: unknown;
};

export type IssueTokenOptions = {
  issuer: string;
  audience?: string | string[];
  expiresInSeconds: number;
};

export type VerifyTokenOptions = {
  issuer: string;
  audience?: string | string[];
  clockSkewSeconds?: number;
};

export interface TokenProvider {
  issueToken(
    payload: TokenPayload,
    options: IssueTokenOptions,
  ): Promise<string>;
  verifyToken(
    token: string,
    options: VerifyTokenOptions,
  ): Promise<TokenPayload>;
}
