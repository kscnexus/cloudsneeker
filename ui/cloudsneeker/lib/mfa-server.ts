// Auth.js side of MFA sign-in (EB-008): `getToken` throws a
// `CredentialsSignin` carrying the MFA code when the API asks for one,
// `authorize` lets it through, and `authenticate` turns it into a result the
// form understands. Server only: it uses the Auth.js error classes, and only
// when a challenge happens, so modules that import it load without them.

import { CredentialsSignin } from "next-auth";

import {
  isMfaChallengeCode,
  type MfaChallengeCode,
  mfaChallengeFromBody,
} from "./mfa";

const MFA_CHALLENGE = Symbol.for("cloudsneeker.mfa-challenge");

/** A `CredentialsSignin` Auth.js reports with `code` set to the challenge. */
export const mfaChallengeError = (
  code: MfaChallengeCode,
): CredentialsSignin => {
  const error = new CredentialsSignin();
  error.code = code;
  Object.defineProperty(error, MFA_CHALLENGE, { value: true });
  return error;
};

export const isMfaChallengeError = (error: unknown): boolean =>
  typeof error === "object" &&
  error !== null &&
  (error as Record<symbol, unknown>)[MFA_CHALLENGE] === true;

/** Throws when a failed token response is an MFA challenge. */
export const throwIfMfaChallenge = async (
  response: Response,
): Promise<void> => {
  if (response.status !== 401) return;
  const body = await response.json().catch(() => null);
  const code = mfaChallengeFromBody(body);
  if (code) throw mfaChallengeError(code);
};

/** Lets an MFA challenge through a catch block that rewraps errors. */
export const rethrowMfaChallenge = (error: unknown): void => {
  if (isMfaChallengeError(error)) throw error;
};

/** `authenticate` result for an MFA challenge, or `null`. */
export const mfaSignInResult = (
  error: unknown,
): { message: MfaChallengeCode } | null => {
  const code = (error as { code?: unknown } | null)?.code;
  return isMfaChallengeCode(code) ? { message: code } : null;
};
