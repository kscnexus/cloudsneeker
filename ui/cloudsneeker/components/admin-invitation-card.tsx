"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";

import { resendAdminInvitation } from "@/cloudsneeker/actions/operator";
import { AdminInvitationLink } from "@/cloudsneeker/components/admin-invitation-link";
import { FormAlert, FormField } from "@/cloudsneeker/components/form-layout";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  invitationFromMeta,
  isErrorResult,
  responseError,
} from "@/cloudsneeker/lib/operator";
import type { TenantInvitation } from "@/cloudsneeker/types/operator";
import { Button, Input } from "@/components/shadcn";

interface AdminInvitationCardProps {
  tenantId: string;
  invitations: TenantInvitation[];
  /** Owner and billing operators may send a new invitation. */
  canResend: boolean;
}

/**
 * Shown while nobody has joined the organization: the pending owner
 * invitation, and a new one when it expired or went to the wrong address.
 */
export const AdminInvitationCard = ({
  tenantId,
  invitations,
  canResend,
}: AdminInvitationCardProps) => {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState<TenantInvitation | null>(null);
  const current = sent ?? invitations[0] ?? null;

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSending(true);
    setError(null);
    const result = await resendAdminInvitation(tenantId, email.trim());
    setSending(false);
    const invitation = invitationFromMeta(result);
    if (isErrorResult(result) || !invitation) {
      setError(responseError(result, "The invitation could not be sent."));
      return;
    }
    setSent(invitation);
    setEmail("");
    router.refresh();
  };

  return (
    <SectionCard
      title="Administrator invitation"
      description="Nobody has joined this organization yet."
    >
      {current ? (
        <AdminInvitationLink invitation={current} />
      ) : (
        <p className="text-text-neutral-secondary text-sm">
          No pending invitation. Send a new one so the administrator can join.
        </p>
      )}
      {canResend ? (
        <form
          onSubmit={onSubmit}
          aria-label="New invitation"
          className="flex flex-col gap-3 sm:flex-row sm:items-end"
        >
          <FormField
            id="invitation-email"
            label="Send to another email"
            optional
            help="Leave empty to invite the same address. The old link stops working."
            className="flex-1"
          >
            <Input
              id="invitation-email"
              type="email"
              value={email}
              autoComplete="off"
              onChange={(event) => setEmail(event.target.value)}
            />
          </FormField>
          <Button type="submit" variant="outline" disabled={sending}>
            {sending ? "Sending…" : "New invitation link"}
          </Button>
        </form>
      ) : null}
      <FormAlert message={error} />
    </SectionCard>
  );
};
