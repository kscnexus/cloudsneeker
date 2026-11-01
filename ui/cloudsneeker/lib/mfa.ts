// Multi-factor authentication (EB-008). Sign-in sends `otp_code` with the
// password once the API answers `mfa_required`. Client-safe helpers; the
// Auth.js error plumbing lives in `mfa-server.ts`.

export const MFA_CODE = {
  REQUIRED: "mfa_required",
  INVALID: "mfa_invalid",
  ENROLMENT_REQUIRED: "mfa_enrolment_required",
} as const;

export type MfaChallengeCode =
  | typeof MFA_CODE.REQUIRED
  | typeof MFA_CODE.INVALID;

const CHALLENGE_CODES: ReadonlySet<string> = new Set([
  MFA_CODE.REQUIRED,
  MFA_CODE.INVALID,
]);

export const isMfaChallengeCode = (value: unknown): value is MfaChallengeCode =>
  typeof value === "string" && CHALLENGE_CODES.has(value);

/** The MFA challenge code in a failed `POST /tokens` body, if any. */
export const mfaChallengeFromBody = (
  body: unknown,
): MfaChallengeCode | null => {
  const errors = (body as { errors?: unknown } | null)?.errors;
  if (!Array.isArray(errors)) return null;
  for (const error of errors) {
    const code = (error as { code?: unknown } | null)?.code;
    if (isMfaChallengeCode(code)) return code;
  }
  return null;
};

/** Adds the code to sign-in credentials when one was entered. */
export const withOtpCode = <T extends object>(
  credentials: T,
  otpCode?: string | null,
): T & { otpCode?: string } => {
  const code = (otpCode ?? "").replace(/[\s-]/g, "");
  return code ? { ...credentials, otpCode: code } : credentials;
};

/** `otp_code` attribute for the `POST /tokens` body. */
export const otpCodeAttribute = (
  credentials: object,
): { otp_code?: string } => {
  const code = (credentials as { otpCode?: unknown }).otpCode;
  return typeof code === "string" && code ? { otp_code: code } : {};
};

/** Groups a base32 secret in fours so it is easier to type. */
export const formatSecret = (secret: string): string =>
  secret.replace(/(.{4})/g, "$1 ").trim();

export const MFA_SIGN_IN_MESSAGE: Record<MfaChallengeCode, string> = {
  [MFA_CODE.REQUIRED]:
    "Enter the 6-digit code from your authenticator app, or a recovery code.",
  [MFA_CODE.INVALID]:
    "That code did not match. Enter a current code or an unused recovery code.",
};

/** Error message of a server action result, or `null` on success. */
export const actionError = (result: unknown): string | null => {
  if (!result || typeof result !== "object") return "No response.";
  const error = (result as { error?: unknown }).error;
  return typeof error === "string" && error ? error : null;
};

/** Recovery codes from a confirm or regenerate action result. */
export const recoveryCodesFromResult = (result: unknown): string[] => {
  const codes = (
    result as { data?: { attributes?: { codes?: unknown } } } | null
  )?.data?.attributes?.codes;
  return Array.isArray(codes)
    ? codes.filter((code): code is string => typeof code === "string")
    : [];
};

/** Plain-text list for copying recovery codes. */
export const recoveryCodesText = (codes: string[]): string =>
  `${codes.join("\n")}\n`;
