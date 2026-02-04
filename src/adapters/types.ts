export type CredentialFailureReason =
  | "INVALID_CREDENTIALS"
  | "USER_NOT_FOUND"
  | "USER_LOCKED"
  | "USER_DISABLED";

export interface CredentialChecker {
  checkUserNamePassword(
    principal: string,
    password: string,
  ): Promise<
    | { ok: true; userId: string }
    | { ok: false; reason?: CredentialFailureReason }
  >;
}

export interface RoleProvider {
  getUserRoles(userId: string): Promise<string[]>;
}

export interface RoleStampProvider {
  getRoleStamp(userId: string): Promise<string>;
}

export interface RoleVersionProvider {
  getRoleVersion(userId: string): Promise<number>;
}

export type AdditionalClaims = Record<string, unknown>;
export interface AdditionalClaimsProvider {
  getAdditionalClaims(input: {
    userId: string;
    principal: string;
  }): Promise<AdditionalClaims>;
}
