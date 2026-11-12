"use client";

import Link from "next/link";
import type { ReactNode } from "react";

import { FindingTriageStatusBadge } from "@/cloudsneeker/components/finding-triage-status-badge";
import { MuteFindingsButton } from "@/cloudsneeker/components/mute-findings-button";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { StandardSeverityBadge } from "@/cloudsneeker/components/standard/standard-severity-badge";
import { AREA_CONFIG } from "@/cloudsneeker/lib/area-findings";
import { formatAuditTime } from "@/cloudsneeker/lib/audit-log";
import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import {
  type AreaFindingAttributes,
  FINDING_AREA,
} from "@/cloudsneeker/types/area-findings";
import {
  InfoField,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/shadcn";
import { Badge } from "@/components/shadcn/badge/badge";

interface GovernanceFindingDetailProps {
  finding: AreaFindingAttributes;
  canTriage: boolean;
}

const Field = ({ label, children }: { label: string; children: ReactNode }) => (
  <InfoField label={label}>
    <span className="break-words">{children}</span>
  </InfoField>
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

  const hasResource = Boolean(resource && Object.keys(resource).length > 0);

  // Same layout as the Cloud Security finding drawer: a header with severity,
  // status and actions, then Overview / Remediation / Evidence tabs.
  return (
    <div className="flex flex-col gap-4">
      <SectionCard title={finding.title || finding.check_id}>
        <div className="flex flex-wrap items-center gap-2">
          <StandardSeverityBadge severity={finding.severity} />
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
        <Tabs defaultValue="overview" className="mt-4 flex w-full flex-col">
          <div className="mb-4 flex items-center justify-between">
            <TabsList>
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="remediation">Remediation</TabsTrigger>
              <TabsTrigger value="evidence">Evidence</TabsTrigger>
            </TabsList>
          </div>
          <TabsContent value="overview" className="flex flex-col gap-4">
            {finding.description ? (
              <p className="text-text-neutral-secondary text-sm">
                {finding.description}
              </p>
            ) : null}
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <Field label="Resource">
                {finding.resource_name || finding.resource_id || "—"}
              </Field>
              <Field label="Resource ID">{finding.resource_id || "—"}</Field>
              <Field label="Resource type">
                {finding.resource_type || "—"}
              </Field>
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
              <Field label="First seen">
                {finding.first_seen_at
                  ? formatAuditTime(finding.first_seen_at)
                  : "—"}
              </Field>
              <Field label="Last seen">
                {finding.last_seen_at
                  ? formatAuditTime(finding.last_seen_at)
                  : "—"}
              </Field>
              <Field label="Finding ID">
                <span className="font-mono text-xs">{finding.uid}</span>
              </Field>
            </div>
          </TabsContent>
          <TabsContent value="remediation" className="flex flex-col gap-4">
            <p className="text-text-neutral-secondary text-sm">
              Fix the resource so the policy no longer matches it; the next dry
              run of the policy closes the finding. Track the work with a triage
              status, or mute the resource with a reason when it is an accepted
              exception.
            </p>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <Field label="Policy">
                {policyHref ? (
                  <Link href={policyHref} className={LINK_CLASS}>
                    Open the policy and its filters
                  </Link>
                ) : (
                  "—"
                )}
              </Field>
              <Field label="Dry run">
                {runHref ? (
                  <Link href={runHref} className={LINK_CLASS}>
                    Open the run that reported it
                  </Link>
                ) : (
                  "—"
                )}
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
            </div>
          </TabsContent>
          <TabsContent value="evidence">
            {hasResource ? (
              <>
                <p className="text-text-neutral-secondary mb-2 text-sm">
                  The resource as the policy run reported it.
                </p>
                <pre className="bg-bg-neutral-tertiary max-h-[480px] overflow-auto rounded-md p-3 text-xs">
                  {JSON.stringify(resource, null, 2)}
                </pre>
              </>
            ) : (
              <p className="text-text-neutral-secondary text-sm">
                The run did not report resource details.
              </p>
            )}
          </TabsContent>
        </Tabs>
      </SectionCard>
    </div>
  );
};
