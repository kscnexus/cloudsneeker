"use client";

import {
  MFA_CODE,
  MFA_SIGN_IN_MESSAGE,
  type MfaChallengeCode,
} from "@/cloudsneeker/lib/mfa";
import { Input, Label } from "@/components/shadcn";

export const MFA_CODE_INPUT_ID = "mfa-otp-code";

interface MfaCodeFieldProps {
  challenge: MfaChallengeCode;
  value: string;
  onChange: (value: string) => void;
}

/** Second sign-in step: authenticator or recovery code (EB-008). */
export const MfaCodeField = ({
  challenge,
  value,
  onChange,
}: MfaCodeFieldProps) => (
  <div className="flex flex-col gap-1.5">
    <Label htmlFor={MFA_CODE_INPUT_ID}>Verification code</Label>
    <Input
      id={MFA_CODE_INPUT_ID}
      name="otpCode"
      inputMode="text"
      autoComplete="one-time-code"
      autoFocus
      maxLength={32}
      placeholder="123456"
      value={value}
      onChange={(event) => onChange(event.target.value)}
      aria-describedby={`${MFA_CODE_INPUT_ID}-hint`}
    />
    <p
      id={`${MFA_CODE_INPUT_ID}-hint`}
      role={challenge === MFA_CODE.INVALID ? "alert" : undefined}
      className={
        challenge === MFA_CODE.INVALID
          ? "text-text-error-primary text-xs"
          : "text-text-neutral-secondary text-xs"
      }
    >
      {MFA_SIGN_IN_MESSAGE[challenge]}
    </p>
  </div>
);
