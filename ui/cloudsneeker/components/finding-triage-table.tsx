import { ExternalLink } from "lucide-react";
import Link from "next/link";

import { AREA_CONFIG, areaFindingHref } from "@/cloudsneeker/lib/area-findings";
import { formatReportDate } from "@/cloudsneeker/lib/report-view";
import { daysUntil } from "@/cloudsneeker/lib/risk-acceptance";
import {
  TABLE_BODY_CLASS,
  TABLE_CLASS,
  TABLE_FRAME_CLASS,
  TABLE_HEADER_CELL_CLASS,
  TABLE_HEAD_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import {
  FINDING_AREA,
  type FindingArea,
} from "@/cloudsneeker/types/area-findings";
import type {
  FindingTriageAttributes,
  FindingTriageResource,
} from "@/cloudsneeker/types/finding-triage";
import { Button } from "@/components/shadcn";
import { cn } from "@/lib/utils";

import { FindingTriageStatusBadge } from "./finding-triage-status-badge";

interface FindingTriageTableProps {
  triages: FindingTriageResource[];
  /** Product area; links go to that area's findings. */
  area?: FindingArea;
}

const HEADERS = ["Status", "Finding", "Latest note", "Updated", ""] as const;

/** Expiry, approver and reason of an accepted risk, or when one expired. */
export const RiskAcceptanceSummary = ({
  attributes,
}: {
  attributes: FindingTriageAttributes;
}) => {
  if (
    attributes.stored_status === "risk_accepted" &&
    attributes.risk_expires_on
  ) {
    const days = daysUntil(attributes.risk_expires_on);
    return (
      <span className="text-text-neutral-tertiary mt-1 flex max-w-56 flex-col text-xs">
        <span
          className={cn(days <= 14 && "text-text-warning-primary font-medium")}
        >
          Until {attributes.risk_expires_on}
          {days >= 0 && days <= 14 ? ` (${days} days left)` : ""}
        </span>
        {attributes.risk_approved_by_name ? (
          <span>Approved by {attributes.risk_approved_by_name}</span>
        ) : null}
        {attributes.risk_reason ? (
          <span className="line-clamp-2" title={attributes.risk_reason}>
            {attributes.risk_reason}
          </span>
        ) : null}
      </span>
    );
  }
  if (attributes.risk_expired_at && attributes.status === "reopened") {
    return (
      <span className="text-text-warning-primary mt-1 block text-xs">
        Risk acceptance expired {attributes.risk_expires_on ?? ""}
      </span>
    );
  }
  return null;
};

/** Triaged findings with a link back to the finding in its area. */
export const FindingTriageTable = ({
  triages,
  area = FINDING_AREA.CLOUD,
}: FindingTriageTableProps) => (
  <div className={TABLE_FRAME_CLASS}>
    <table className={TABLE_CLASS}>
      <thead className={TABLE_HEAD_CLASS}>
        <tr>
          {HEADERS.map((header) => (
            <th
              key={header || "actions"}
              scope="col"
              className={TABLE_HEADER_CELL_CLASS}
            >
              {header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody className={TABLE_BODY_CLASS}>
        {triages.map((triage) => {
          const attributes = triage.attributes;
          return (
            <tr key={triage.id}>
              <td className="px-3 py-2">
                <FindingTriageStatusBadge status={attributes.status} />
                <RiskAcceptanceSummary attributes={attributes} />
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
                  <Link
                    href={areaFindingHref(area, {
                      uid: attributes.finding_uid,
                      checkId: attributes.check_id,
                    })}
                  >
                    <ExternalLink aria-hidden="true" />
                    {area === FINDING_AREA.CLOUD
                      ? "Open in Findings"
                      : `Open in ${AREA_CONFIG[area].name} findings`}
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
