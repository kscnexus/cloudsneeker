import Link from "next/link";
import type { ReactNode } from "react";

import {
  categoryImpact,
  categoryLabel,
  dueText,
  validationSteps,
} from "@/cloudsneeker/lib/app-security-finding-detail";
import { RISK_PRIORITY_RULES } from "@/cloudsneeker/lib/app-security-priority";
import {
  areaFindingsPageHref,
  areaTriagePageHref,
} from "@/cloudsneeker/lib/area-findings";
import { formatReportDate } from "@/cloudsneeker/lib/report-view";
import { APP_SECURITY_SEGMENT, appSecurityHref } from "@/cloudsneeker/routes";
import {
  type AreaFindingAttributes,
  FINDING_AREA,
} from "@/cloudsneeker/types/area-findings";
import { Button } from "@/components/shadcn";

import { AreaFindingExploitDetails } from "./area-finding-exploit";
import { AreaFindingFixDetails } from "./area-finding-fix";
import { FindingTriageStatusBadge } from "./finding-triage-status-badge";
import { StandardSeverityBadge } from "@/cloudsneeker/components/standard/standard-severity-badge";
import { RiskPriorityBadge } from "./risk-priority-badge";
import { SectionCard } from "./section-card";

const Field = ({ label, children }: { label: string; children: ReactNode }) => (
  <div className="flex min-w-0 flex-col gap-0.5">
    <dt className="text-text-neutral-tertiary text-xs font-semibold">
      {label}
    </dt>
    <dd className="text-text-neutral-primary text-sm break-words">
      {children}
    </dd>
  </div>
);

const LinkText = ({
  href,
  children,
}: {
  href: string;
  children: ReactNode;
}) => (
  <Link href={href} className="underline-offset-2 hover:underline">
    {children}
  </Link>
);

/** Every section of one finding: what, where, why, fix, verify, status. */
export const AppSecurityFindingDetail = ({
  finding,
}: {
  finding: AreaFindingAttributes;
}) => {
  const area = FINDING_AREA.APPLICATION_SECURITY;
  const impact = categoryImpact(finding.security_category);
  const triageHref = areaFindingsPageHref(area, { search: finding.uid });

  return (
    <div className="flex flex-col gap-6">
      <SectionCard title="Summary" contentClassName="p-4 sm:p-5">
        <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Severity">
            <StandardSeverityBadge severity={finding.severity} />
          </Field>
          <Field label="Risk priority">
            <span title={RISK_PRIORITY_RULES}>
              <RiskPriorityBadge
                priority={finding.priority}
                overdue={finding.overdue}
              />
            </span>
          </Field>
          <Field label="Category">
            {finding.security_category ? (
              <LinkText
                href={areaFindingsPageHref(area, {
                  category: finding.security_category,
                })}
              >
                {categoryLabel(finding.security_category)}
              </LinkText>
            ) : (
              "—"
            )}
          </Field>
          <Field label="Status">
            <FindingTriageStatusBadge status={finding.triage_status} />
          </Field>
          <Field label="Remediation due">
            {finding.due_at
              ? `${formatReportDate(finding.due_at)} · ${dueText(finding.due_at, finding.overdue)}`
              : "—"}
          </Field>
          <Field label="First seen">
            {formatReportDate(finding.first_seen_at)}
          </Field>
          <Field label="Last seen">
            {formatReportDate(finding.last_seen_at)}
          </Field>
          <Field label="Rule or CVE">
            <span className="font-mono text-xs">{finding.check_id}</span>
          </Field>
        </dl>
      </SectionCard>

      <div className="grid gap-6 lg:grid-cols-2">
        <SectionCard title="Where it is" contentClassName="p-4 sm:p-5">
          <dl className="grid gap-4">
            <Field label="Application">
              {finding.provider_id ? (
                <LinkText
                  href={appSecurityHref(
                    APP_SECURITY_SEGMENT.APPLICATIONS,
                    finding.provider_id,
                  )}
                >
                  Open the application
                </LinkText>
              ) : (
                "—"
              )}
            </Field>
            <Field label="Target">
              {finding.source_id ? (
                <LinkText href={appSecurityHref(finding.source_id)}>
                  {finding.source_name || finding.source_id}
                </LinkText>
              ) : (
                finding.source_name || "—"
              )}
            </Field>
            <Field label="Location">
              <span className="font-mono text-xs">
                {finding.location || "—"}
              </span>
            </Field>
            <Field label="Resource">
              <span className="font-mono text-xs break-all">
                {finding.resource_id || finding.resource_name || "—"}
              </span>
            </Field>
          </dl>
        </SectionCard>

        <SectionCard title="Why it matters" contentClassName="p-4 sm:p-5">
          <dl className="grid gap-4">
            {impact ? <Field label="Impact">{impact}</Field> : null}
            <AreaFindingExploitDetails finding={finding} />
            {!impact &&
            !finding.known_exploited &&
            finding.epss_score === null ? (
              <p className="text-text-neutral-tertiary text-sm">
                No exploit intelligence for this finding.
              </p>
            ) : null}
          </dl>
        </SectionCard>
      </div>

      <SectionCard title="What is wrong" contentClassName="p-4 sm:p-5">
        <div className="flex flex-col gap-3 text-sm">
          <p className="text-text-neutral-primary whitespace-pre-line">
            {finding.description || "No description from the scanner."}
          </p>
          {finding.status_extended &&
          finding.status_extended !== finding.description ? (
            <div>
              <h3 className="text-text-neutral-tertiary text-xs font-semibold">
                Evidence
              </h3>
              <p className="text-text-neutral-secondary font-mono text-xs whitespace-pre-line">
                {finding.status_extended}
              </p>
            </div>
          ) : null}
        </div>
      </SectionCard>

      <div className="grid gap-6 lg:grid-cols-2">
        <SectionCard title="How to fix" contentClassName="p-4 sm:p-5">
          <dl className="grid gap-4">
            <AreaFindingFixDetails finding={finding} />
          </dl>
        </SectionCard>
        <SectionCard
          title="How to verify the fix"
          contentClassName="p-4 sm:p-5"
        >
          <ol className="text-text-neutral-primary flex list-decimal flex-col gap-2 pl-5 text-sm">
            {validationSteps(finding.security_category).map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
          {finding.source_id ? (
            <Button asChild size="sm" variant="outline" className="mt-4">
              <Link href={appSecurityHref(finding.source_id)}>
                Open the target to rescan
              </Link>
            </Button>
          ) : null}
        </SectionCard>
      </div>

      <SectionCard
        title="Assignment and status"
        description="Status, assignee and notes follow this finding across rescans."
        contentClassName="p-4 sm:p-5"
        actions={
          <Button asChild size="sm" variant="outline">
            <Link href={triageHref}>Change status</Link>
          </Button>
        }
      >
        <dl className="grid gap-4 sm:grid-cols-3">
          <Field label="Status">
            <FindingTriageStatusBadge status={finding.triage_status} />
          </Field>
          <Field label="Assigned">
            {finding.assignee_id ? "Assigned" : "Unassigned"}
          </Field>
          <Field label="Notes">
            {finding.triage_notes_count > 0 ? (
              <LinkText href={areaTriagePageHref(area, null)}>
                {`${finding.triage_notes_count} note(s)`}
              </LinkText>
            ) : (
              "No notes"
            )}
          </Field>
          {finding.triage_latest_note ? (
            <div className="sm:col-span-3">
              <Field label="Latest note">{finding.triage_latest_note}</Field>
            </div>
          ) : null}
          {finding.risk_reason ? (
            <div className="sm:col-span-3">
              <Field label="Accepted risk">
                {`${finding.risk_reason}${finding.risk_expires_on ? ` (until ${formatReportDate(finding.risk_expires_on)})` : ""}`}
              </Field>
            </div>
          ) : null}
        </dl>
      </SectionCard>
    </div>
  );
};
