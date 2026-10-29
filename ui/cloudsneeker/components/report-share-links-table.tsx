"use client";

import { Link2Off } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { revokeReportShareLink } from "@/cloudsneeker/actions/reports";
import { formatReportDate } from "@/cloudsneeker/lib/report-view";
import { reportsHref } from "@/cloudsneeker/routes";
import {
  SHARE_LINK_STATE,
  type ReportShareLinkResource,
  type ShareLinkState,
} from "@/cloudsneeker/types/reports";
import { Badge, Button } from "@/components/shadcn";

const STATE_BADGE: Record<
  ShareLinkState,
  { label: string; variant: "success" | "warning" | "error" }
> = {
  [SHARE_LINK_STATE.ACTIVE]: { label: "Active", variant: "success" },
  [SHARE_LINK_STATE.EXPIRED]: { label: "Expired", variant: "warning" },
  [SHARE_LINK_STATE.REVOKED]: { label: "Revoked", variant: "error" },
};

interface ReportShareLinksTableProps {
  links: ReportShareLinkResource[];
  /** Report name per run id, from the recent runs list. */
  runNames: Record<string, string>;
  canManage: boolean;
}

export const ReportShareLinksTable = ({
  links,
  runNames,
  canManage,
}: ReportShareLinksTableProps) => {
  const router = useRouter();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!canManage) {
    return (
      <p className="text-text-neutral-secondary text-sm">
        Managing share links needs the manage scans permission.
      </p>
    );
  }

  if (links.length === 0) {
    return (
      <p className="text-text-neutral-secondary border-border-neutral-secondary rounded-xl border border-dashed p-6 text-sm">
        No share links yet. Use Share on a ready report to create one.
      </p>
    );
  }

  const onRevoke = async (linkId: string) => {
    setBusy(linkId);
    setError(null);
    const result = await revokeReportShareLink(linkId);
    setBusy(null);
    if (result && "error" in result && result.error) {
      setError(
        typeof result.error === "string" ? result.error : "Revoke failed.",
      );
      return;
    }
    router.refresh();
  };

  return (
    <div className="flex flex-col gap-2">
      <p className="text-text-neutral-secondary text-sm">
        Links are shown once when created. Revoke a link to stop access
        immediately.
      </p>
      {error ? <p className="text-text-error-primary text-sm">{error}</p> : null}
      <div className="border-border-neutral-secondary overflow-x-auto rounded-xl border">
        <table className="w-full text-left text-sm">
          <thead className="bg-bg-neutral-tertiary">
            <tr>
              {["Report", "State", "Created", "Expires", "Views", ""].map(
                (header, index) => (
                  <th
                    key={`${header}-${index}`}
                    scope="col"
                    className="text-text-neutral-secondary px-3 py-2 text-xs font-semibold"
                  >
                    {header}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody className="divide-border-neutral-secondary divide-y">
            {links.map((link) => {
              const attributes = link.attributes;
              const state = STATE_BADGE[attributes.state] ?? {
                label: attributes.state,
                variant: "warning" as const,
              };
              const runName = runNames[attributes.report_run_id];
              return (
                <tr key={link.id}>
                  <td className="px-3 py-2">
                    <Link
                      href={reportsHref(attributes.report_run_id)}
                      className="text-text-neutral-primary underline-offset-2 hover:underline"
                    >
                      {runName ?? "Report"}
                    </Link>
                  </td>
                  <td className="px-3 py-2">
                    <Badge variant={state.variant}>{state.label}</Badge>
                  </td>
                  <td className="text-text-neutral-secondary px-3 py-2 text-xs whitespace-nowrap">
                    {formatReportDate(attributes.inserted_at)}
                  </td>
                  <td className="text-text-neutral-secondary px-3 py-2 text-xs whitespace-nowrap">
                    {formatReportDate(attributes.expires_at)}
                  </td>
                  <td className="text-text-neutral-secondary px-3 py-2 text-xs">
                    {attributes.access_count}
                    {attributes.last_accessed_at
                      ? ` · last ${formatReportDate(attributes.last_accessed_at)}`
                      : ""}
                  </td>
                  <td className="px-3 py-2 text-right">
                    {attributes.state === SHARE_LINK_STATE.ACTIVE ? (
                      <Button
                        type="button"
                        variant="ghost"
                        size="xs"
                        disabled={busy === link.id}
                        onClick={() => onRevoke(link.id)}
                      >
                        <Link2Off aria-hidden="true" />
                        Revoke
                      </Button>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
