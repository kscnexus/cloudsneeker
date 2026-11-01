"use client";

import { useSyncExternalStore } from "react";

import { formatPlanDate } from "@/cloudsneeker/lib/entitlements";
import type { TenantInvitation } from "@/cloudsneeker/types/operator";
import { CodeSnippet } from "@/components/shadcn/code-snippet/code-snippet";
import { buildInvitationAcceptLink } from "@/lib/invitations/accept-link";

const subscribe = () => () => {};
const browserOrigin = () => window.location.origin;
const serverOrigin = () => "";

interface AdminInvitationLinkProps {
  invitation: TenantInvitation;
}

/**
 * Accept link of a new customer's owner invitation. Nothing is emailed: the
 * operator sends the link. The origin is read in the browser, so the link
 * points at the host the operator is using.
 */
export const AdminInvitationLink = ({
  invitation,
}: AdminInvitationLinkProps) => {
  const origin = useSyncExternalStore(subscribe, browserOrigin, serverOrigin);

  return (
    <div className="flex min-w-0 flex-col gap-2" data-slot="admin-invitation">
      <p className="text-text-neutral-secondary text-sm">
        Send this link to{" "}
        <span className="text-text-neutral-primary font-medium">
          {invitation.email}
        </span>
        . It expires on {formatPlanDate(invitation.expires_at)}. They set their
        own password and become the organization&apos;s owner.
      </p>
      {invitation.token && origin ? (
        <CodeSnippet
          value={buildInvitationAcceptLink(invitation.token, origin)}
          className="max-w-full"
        />
      ) : null}
    </div>
  );
};
