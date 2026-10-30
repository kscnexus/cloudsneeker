import { ExternalLink } from "lucide-react";
import Link from "next/link";

import { triageFindingsHref } from "@/cloudsneeker/lib/finding-triage";
import { formatReportDate } from "@/cloudsneeker/lib/report-view";
import type { FindingTriageResource } from "@/cloudsneeker/types/finding-triage";
import { Button } from "@/components/shadcn";

import { FindingTriageStatusBadge } from "./finding-triage-status-badge";

interface FindingTriageTableProps {
  triages: FindingTriageResource[];
}

const HEADERS = ["Status", "Finding", "Latest note", "Updated", ""] as const;

/** Triaged findings with a link back to the finding on the Findings page. */
export const FindingTriageTable = ({ triages }: FindingTriageTableProps) => (
  <div className="border-border-neutral-secondary overflow-x-auto rounded-xl border">
    <table className="w-full text-left text-sm">
      <thead className="bg-bg-neutral-tertiary">
        <tr>
          {HEADERS.map((header) => (
            <th
              key={header || "actions"}
              scope="col"
              className="text-text-neutral-secondary px-3 py-2 text-xs font-semibold"
            >
              {header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody className="divide-border-neutral-secondary divide-y">
        {triages.map((triage) => {
          const attributes = triage.attributes;
          return (
            <tr key={triage.id}>
              <td className="px-3 py-2 whitespace-nowrap">
                <FindingTriageStatusBadge status={attributes.status} />
              </td>
              <td className="max-w-md px-3 py-2">
                <div className="flex min-w-0 flex-col">
                  <span className="text-text-neutral-primary truncate font-medium">
                    {attributes.check_id || "Finding"}
                  </span>
                  <span
                    className="text-text-neutral-tertiary truncate font-mono text-xs"
                    title={attributes.finding_uid}
                  >
                    {attributes.finding_uid}
                  </span>
                </div>
              </td>
              <td className="text-text-neutral-secondary max-w-xs px-3 py-2 text-xs">
                {attributes.current_note ? (
                  <span className="line-clamp-2 whitespace-pre-line">
                    {attributes.current_note}
                  </span>
                ) : (
                  "—"
                )}
                {attributes.triage_notes_count > 1 ? (
                  <span className="text-text-neutral-tertiary block">
                    {attributes.triage_notes_count} notes
                  </span>
                ) : null}
              </td>
              <td className="text-text-neutral-secondary px-3 py-2 text-xs whitespace-nowrap">
                {formatReportDate(attributes.updated_at)}
              </td>
              <td className="px-3 py-2">
                <Button asChild variant="outline" size="xs">
                  <Link href={triageFindingsHref(attributes.check_id)}>
                    <ExternalLink aria-hidden="true" />
                    Open in Findings
                  </Link>
                </Button>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);
