import type { AuthError } from "./errors/error.js";
import type {
  CredentialChecker,
  RoleProvider,
  RoleStampProvider,
  RoleVersionProvider,
} from "./adapters/types.js";
import type { TokenPayload, TokenProvider } from "./token/types.js";

export type AuthCoreConfig = {
  issuer: string;
  audience?: string | string[];
  tokenTtlSeconds: number;

  roleFreshness?: {
    enabled: boolean;
  };

  clockSkewSeconds?: number;
};

export type AuthCoreAdapters = {
  credentialChecker: CredentialChecker;
  roleProvider: RoleProvider;
  roleStampProvider?: RoleStampProvider; // new
  roleVersionProvider?: RoleVersionProvider; // keep
  tokenProvider: TokenProvider;
};

export type AuthenticateInput = {
  principal: string;
  password: string;
};

export type AuthenticateResult =
  | {
      ok: true;
      accessToken: string;
      expiresAt: string;
      userId: string;
      roles: string[];
      roleStamp?: string;
      roleVersion?: number;
    }
  | {
      ok: false;
      error: AuthError;
    };

export type AuthorizeInput = {
  token: string;
  required?: {
    anyRoles?: string[];
    allRoles?: string[];
  };
  expectedAudience?: string | string[];
};

export type AuthorizeResult =
  | {
      ok: true;
      userId: string;
      roles: string[];
      roleStamp?: string;
      roleVersion?: number;
      principal?: string;
      claims: TokenPayload;
    }
  | {
      ok: false;
      error: AuthError;
    };

export interface AuthCore {
  doAuthenticate(input: AuthenticateInput): Promise<AuthenticateResult>;
  doAuthorize(input: AuthorizeInput): Promise<AuthorizeResult>;
}
