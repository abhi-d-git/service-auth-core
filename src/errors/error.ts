import type { AuthErrorCode } from "./codes.js";

export type AuthError = {
  code: AuthErrorCode;
  message: string;
  details?: unknown;
};

export function err(
  code: AuthErrorCode,
  message: string,
  details?: unknown,
): AuthError {
  return { code, message, ...(details !== undefined ? { details } : {}) };
}
