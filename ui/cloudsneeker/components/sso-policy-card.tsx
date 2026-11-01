"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { setRejectIdpInitiatedSso } from "@/cloudsneeker/actions/sso";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { actionError } from "@/cloudsneeker/lib/mfa";
import type { SsoPolicyAttributes } from "@/cloudsneeker/types/mfa";
import { Button } from "@/components/shadcn";
import { useToast } from "@/components/shadcn/toast/use-toast";

/** Admin SAML options on the Security page (EB-009). */
export const SsoPolicyCard = ({ policy }: { policy: SsoPolicyAttributes }) => {
  const router = useRouter();
  const { toast } = useToast();
  const [busy, setBusy] = useState(false);
  const reject = policy.reject_idp_initiated_sso;

  const toggle = async () => {
    setBusy(true);
    try {
      const error = actionError(await setRejectIdpInitiatedSso(!reject));
      if (error) {
        toast({
          variant: "destructive",
          title: "Could not change single sign-on",
          description: error,
        });
        return;
      }
      router.refresh();
    } finally {
      setBusy(false);
    }
  };

  return (
    <SectionCard
      title="Single sign-on (SAML)"
      description="Applies when SAML is set up under Integrations. Your identity provider must sign its assertions."
    >
      <div className="flex flex-col gap-3 text-sm">
        <ul className="text-text-neutral-secondary flex list-disc flex-col gap-1 pl-5">
          <li>Signed assertions required: yes</li>
          <li>
            Sign-in requests signed by this platform:{" "}
            {policy.signed_requests ? "yes" : "no (no signing key configured)"}
          </li>
        </ul>
        <div className="flex flex-wrap items-center gap-3">
          <span>
            {reject
              ? "Only sign-ins started on this site are accepted."
              : "Sign-ins started from the identity provider's app list are accepted."}
          </span>
          <Button size="sm" variant="outline" disabled={busy} onClick={toggle}>
            {reject
              ? "Allow sign-in from the identity provider"
              : "Only allow sign-in started here"}
          </Button>
        </div>
      </div>
    </SectionCard>
  );
};
