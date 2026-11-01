"use client";

import { Copy, KeyRound, ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  confirmMfaEnrolment,
  disableMfa,
  regenerateMfaRecoveryCodes,
  setTenantMfaRequirement,
  startMfaEnrolment,
} from "@/cloudsneeker/actions/mfa";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  actionError,
  formatSecret,
  recoveryCodesFromResult,
  recoveryCodesText,
} from "@/cloudsneeker/lib/mfa";
import type {
  MfaEnrolmentAttributes,
  MfaStatusAttributes,
} from "@/cloudsneeker/types/mfa";
import { Button, Input, Label } from "@/components/shadcn";
import { useToast } from "@/components/shadcn/toast/use-toast";

interface MfaSettingsProps {
  status: MfaStatusAttributes;
  canManageAccount: boolean;
}

const CODE_INPUT_ID = "mfa-settings-code";

const CodeInput = ({
  value,
  onChange,
  label,
}: {
  value: string;
  onChange: (value: string) => void;
  label: string;
}) => (
  <div className="flex max-w-xs flex-col gap-1.5">
    <Label htmlFor={CODE_INPUT_ID}>{label}</Label>
    <Input
      id={CODE_INPUT_ID}
      inputMode="numeric"
      autoComplete="one-time-code"
      maxLength={32}
      placeholder="123456"
      value={value}
      onChange={(event) => onChange(event.target.value)}
    />
  </div>
);

const RecoveryCodes = ({
  codes,
  onDone,
}: {
  codes: string[];
  onDone: () => void;
}) => {
  const { toast } = useToast();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(recoveryCodesText(codes));
      toast({ title: "Recovery codes copied" });
    } catch {
      toast({
        variant: "destructive",
        title: "Could not copy",
        description: "Select the codes and copy them by hand.",
      });
    }
  };
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm">
        Save these recovery codes somewhere safe, such as a password manager.
        Each one signs you in once if you lose your phone. They are shown only
        now.
      </p>
      <ul
        aria-label="Recovery codes"
        className="bg-bg-neutral-tertiary grid grid-cols-2 gap-2 rounded-lg p-4 font-mono text-sm"
      >
        {codes.map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ul>
      <div className="flex gap-2">
        <Button size="sm" variant="outline" onClick={copy}>
          <Copy aria-hidden className="size-4" />
          Copy codes
        </Button>
        <Button size="sm" onClick={onDone}>
          I saved them
        </Button>
      </div>
    </div>
  );
};

export const MfaSettings = ({ status, canManageAccount }: MfaSettingsProps) => {
  const router = useRouter();
  const { toast } = useToast();
  const [enrolment, setEnrolment] = useState<MfaEnrolmentAttributes | null>(
    null,
  );
  const [codes, setCodes] = useState<string[] | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);

  const run = async (
    action: () => Promise<unknown>,
    failureTitle: string,
    onSuccess: (result: unknown) => void,
  ) => {
    setBusy(true);
    try {
      const result = await action();
      const error = actionError(result);
      if (error) {
        toast({
          variant: "destructive",
          title: failureTitle,
          description: error,
        });
        return;
      }
      setCode("");
      onSuccess(result);
    } finally {
      setBusy(false);
    }
  };

  const finish = () => {
    setCodes(null);
    setEnrolment(null);
    router.refresh();
  };

  if (!status.applies) {
    return (
      <SectionCard
        title="Multi-factor authentication"
        description="You sign in through your organization's identity provider, which handles the second factor for this account."
      >
        <p className="text-text-neutral-secondary text-sm">
          Nothing to set up here.
        </p>
      </SectionCard>
    );
  }

  const tenantCard = canManageAccount ? (
    <SectionCard
      title="Organization requirement"
      description="Require every member who signs in with a password to use an authenticator app. Members without one are taken to this page until they set it up. Single sign-on users are not affected."
    >
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-sm">
          {status.tenant_requires_mfa
            ? "MFA is required in this organization."
            : "MFA is optional in this organization."}
        </span>
        <Button
          size="sm"
          variant={status.tenant_requires_mfa ? "outline" : "default"}
          disabled={busy}
          onClick={() =>
            run(
              () => setTenantMfaRequirement(!status.tenant_requires_mfa),
              "Could not change the requirement",
              () => router.refresh(),
            )
          }
        >
          {status.tenant_requires_mfa ? "Stop requiring MFA" : "Require MFA"}
        </Button>
      </div>
    </SectionCard>
  ) : null;

  if (codes) {
    return (
      <SectionCard title="Recovery codes">
        <RecoveryCodes codes={codes} onDone={finish} />
      </SectionCard>
    );
  }

  if (!status.enabled) {
    return (
      <div className="flex flex-col gap-6">
        <SectionCard
          title="Multi-factor authentication"
          description="Add an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Authy) so a stolen password is not enough to sign in."
        >
          {status.enrolment_required ? (
            <p role="alert" className="text-text-error-primary mb-3 text-sm">
              Your organization requires MFA. Set it up to continue using the
              app.
            </p>
          ) : null}
          {enrolment ? (
            <div className="flex flex-col gap-4">
              <ol className="flex list-decimal flex-col gap-2 pl-5 text-sm">
                <li>
                  In your authenticator app, add an account and enter this key
                  (time-based):
                  <code className="bg-bg-neutral-tertiary mt-1 block w-fit rounded px-2 py-1 font-mono">
                    {formatSecret(enrolment.secret)}
                  </code>
                  On a phone you can{" "}
                  <a className="underline" href={enrolment.otpauth_uri}>
                    open it in your authenticator app
                  </a>{" "}
                  instead.
                </li>
                <li>Enter the 6-digit code the app shows.</li>
              </ol>
              <CodeInput value={code} onChange={setCode} label="Code" />
              <div>
                <Button
                  size="sm"
                  disabled={busy || !code.trim()}
                  onClick={() =>
                    run(
                      () => confirmMfaEnrolment(code),
                      "Could not turn on MFA",
                      (result) => setCodes(recoveryCodesFromResult(result)),
                    )
                  }
                >
                  <ShieldCheck aria-hidden className="size-4" />
                  Turn on MFA
                </Button>
              </div>
            </div>
          ) : (
            <Button
              size="sm"
              disabled={busy}
              onClick={() =>
                run(startMfaEnrolment, "Could not start setup", (result) =>
                  setEnrolment(
                    (result as { data: { attributes: MfaEnrolmentAttributes } })
                      .data.attributes,
                  ),
                )
              }
            >
              <KeyRound aria-hidden className="size-4" />
              Set up authenticator app
            </Button>
          )}
        </SectionCard>
        {tenantCard}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <SectionCard
        title="Multi-factor authentication"
        description="Sign-in asks for a code from your authenticator app after your password."
      >
        <div className="flex flex-col gap-4">
          <p className="text-sm">
            <ShieldCheck
              aria-hidden
              className="text-text-success-primary mr-1 inline size-4"
            />
            On. {status.recovery_codes_remaining} unused recovery code
            {status.recovery_codes_remaining === 1 ? "" : "s"} left.
          </p>
          <CodeInput
            value={code}
            onChange={setCode}
            label="Current code (needed to change MFA)"
          />
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              variant="outline"
              disabled={busy || !code.trim()}
              onClick={() =>
                run(
                  () => regenerateMfaRecoveryCodes(code),
                  "Could not create new recovery codes",
                  (result) => setCodes(recoveryCodesFromResult(result)),
                )
              }
            >
              New recovery codes
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={busy || !code.trim() || status.tenant_requires_mfa}
              onClick={() =>
                run(
                  () => disableMfa(code),
                  "Could not turn off MFA",
                  () => router.refresh(),
                )
              }
            >
              Turn off MFA
            </Button>
          </div>
          {status.tenant_requires_mfa ? (
            <p className="text-text-neutral-secondary text-xs">
              Your organization requires MFA, so it cannot be turned off.
            </p>
          ) : null}
        </div>
      </SectionCard>
      {tenantCard}
    </div>
  );
};
