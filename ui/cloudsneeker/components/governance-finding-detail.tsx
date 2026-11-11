import Link from "next/link";
import type { ReactNode } from "react";

import { FindingTriageStatusBadge } from "@/cloudsneeker/components/finding-triage-status-badge";
import { MuteFindingsButton } from "@/cloudsneeker/components/mute-findings-button";
import { ReportSeverityBadge } from "@/cloudsneeker/components/report-severity-badge";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { AREA_CONFIG } from "@/cloudsneeker/lib/area-findings";
import { formatAuditTime } from "@/cloudsneeker/lib/audit-log";
import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import {
  type AreaFindingAttributes,
  FINDING_AREA,
} from "@/cloudsneeker/types/area-findings";
import { Badge } from "@/components/shadcn/badge/badge";

interface GovernanceFindingDetailProps {
  finding: AreaFindingAttributes;
  canTriage: boolean;
}

interface FieldProps {
  label: string;
  children: ReactNode;
}

const Field = ({ label, children }: FieldProps) => (
  <div className="flex flex-col gap-0.5">
    <dt className="text-text-neutral-tertiary text-xs font-semibold">
      {label}
    </dt>
    <dd className="text-text-neutral-primary text-sm break-words">
      {children}
    </dd>
  </div>
);

const LINK_CLASS = "underline underline-offset-2";

/** One resource a governance policy matched: what, where, which policy and
 * run, triage and mute state, and the resource as the run reported it. */
export const GovernanceFindingDetail = ({
  finding,
  canTriage,
}: GovernanceFindingDetailProps) => {
  const policyHref = finding.source_id
    ? `${PRODUCT_ROUTE.GOVERNANCE}/${finding.source_id}`
    : null;
  const runHref =
    policyHref && finding.run_id
      ? `${policyHref}/runs/${finding.run_id}`
      : null;
  const resource = finding.resource_details;

  return (
    <div className="flex flex-col gap-4">
      <SectionCard title={finding.title || finding.check_id}>
        <div className="flex flex-wrap items-center gap-2">
          <ReportSeverityBadge severity={finding.severity} />
          {finding.muted ? (
            <Badge variant="tag">Muted</Badge>
          ) : (
            <FindingTriageStatusBadge status={finding.triage_status} />
          )}
          {canTriage && !finding.muted ? (
            <MuteFindingsButton
              findingUids={[finding.uid]}
              label="Governance finding"
            />
          ) : null}
        </div>
        {finding.muted ? (
          <p className="text-text-neutral-secondary mt-3 text-sm">
            Muted by a mutelist rule
            {finding.muted_reason ? `: ${finding.muted_reason}` : ""}.{" "}
            <Link href="/mutelist" className={LINK_CLASS}>
              Open the mutelist
            </Link>
          </p>
        ) : null}
        {finding.description ? (
          <p className="text-text-neutral-secondary mt-3 text-sm">
            {finding.description}
          </p>
        ) : null}
        <dl className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="Resource">
            {finding.resource_name || finding.resource_id || "—"}
          </Field>
          <Field label="Resource ID">{finding.resource_id || "—"}</Field>
          <Field label="Resource type">{finding.resource_type || "—"}</Field>
          <Field label="Region">{finding.region || "—"}</Field>
          <Field label="Policy">
            {policyHref ? (
              <Link href={policyHref} className={LINK_CLASS}>
                {finding.source_name || "Policy"}
              </Link>
            ) : (
              finding.source_name || "—"
            )}
          </Field>
          <Field label="Rule">{finding.check_id || "—"}</Field>
          <Field label="Dry run">
            {runHref ? (
              <Link href={runHref} className={LINK_CLASS}>
                Open the run that reported it
              </Link>
            ) : (
              "—"
            )}
          </Field>
          <Field label="First seen">
            {finding.first_seen_at
              ? formatAuditTime(finding.first_seen_at)
              : "—"}
          </Field>
          <Field label="Last seen">
            {finding.last_seen_at ? formatAuditTime(finding.last_seen_at) : "—"}
          </Field>
          <Field label="Triage">
            <Link
              href={AREA_CONFIG[FINDING_AREA.GOVERNANCE].triageHref}
              className={LINK_CLASS}
            >
              {finding.triage_notes_count > 0
                ? `${finding.triage_notes_count} note(s) · open triage`
                : "Open triage"}
            </Link>
          </Field>
          <Field label="Finding ID">
            <span className="font-mono text-xs">{finding.uid}</span>
          </Field>
        </dl>
      </SectionCard>
      {resource && Object.keys(resource).length > 0 ? (
        <SectionCard
          title="Resource details"
          description="The resource as the policy run reported it."
        >
          <pre className="bg-bg-neutral-tertiary max-h-[480px] overflow-auto rounded-md p-3 text-xs">
            {JSON.stringify(resource, null, 2)}
          </pre>
        </SectionCard>
      ) : null}
    </div>
  );
};
