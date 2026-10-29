import { Shield } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import {
  getCustodianPolicy,
  getCustodianRun,
} from "@/cloudsneeker/actions/custodian";
import { CustodianCancelRunButton } from "@/cloudsneeker/components/custodian-cancel-run-button";
import { CustodianRunResourcesTable } from "@/cloudsneeker/components/custodian-run-resources-table";
import {
  formatDuration,
  runDurationMs,
} from "@/cloudsneeker/lib/custodian-dashboard";
import { normalizeCustodianResources } from "@/cloudsneeker/lib/custodian-resources";
import { findingsHrefForChecks } from "@/cloudsneeker/lib/custodian-templates";
import { governanceHref } from "@/cloudsneeker/routes";
import {
  CUSTODIAN_RUN_STATUS,
  type CustodianPolicyResource,
  type CustodianRunResource,
} from "@/cloudsneeker/types/custodian";
import { Button } from "@/components/shadcn";
import { Badge } from "@/components/shadcn/badge/badge";
import { ContentLayout } from "@/components/shadcn/content-layout";
import {
  Section,
  SectionContent,
  SectionDescription,
  SectionHeader,
  SectionTitle,
} from "@/components/shadcn/section/section";

import { CustodianDownloadYamlButton } from "./download-yaml-button";

interface CustodianRunDetailPageProps {
  params: Promise<{ policyId: string; runId: string }>;
}

export default async function CustodianRunDetailPage({
  params,
}: CustodianRunDetailPageProps) {
  const { policyId, runId } = await params;
  const [policyResponse, runResponse] = await Promise.all([
    getCustodianPolicy(policyId),
    getCustodianRun(runId),
  ]);

  if (
    !policyResponse ||
    ("error" in policyResponse && policyResponse.error) ||
    !policyResponse.data ||
    Array.isArray(policyResponse.data)
  ) {
    notFound();
  }

  if (
    !runResponse ||
    ("error" in runResponse && runResponse.error) ||
    !runResponse.data ||
    Array.isArray(runResponse.data)
  ) {
    notFound();
  }

  const policy = policyResponse.data as CustodianPolicyResource;
  const run = runResponse.data as CustodianRunResource;

  if (run.attributes.policy_id !== policyId) {
    notFound();
  }

  const resources = normalizeCustodianResources(run.attributes.output);
  const resourceCount =
    run.attributes.summary?.resource_count ?? resources.length;
  const duration = formatDuration(
    runDurationMs(run.attributes.started_at, run.attributes.finished_at),
  );
  const providerLabel =
    run.attributes.provider_alias ||
    run.attributes.provider_uid ||
    policy.attributes.provider_alias ||
    policy.attributes.provider_uid ||
    "—";
  const prowlerCheckIds = run.attributes.summary?.prowler_check_ids ?? [];
  const findingsHref = findingsHrefForChecks(prowlerCheckIds);
  const isPending = run.attributes.status === CUSTODIAN_RUN_STATUS.PENDING;

  return (
    <ContentLayout title={policy.attributes.name} icon={<Shield />}>
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="flex max-w-3xl flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="tag" className="capitalize">
              {run.attributes.status}
            </Badge>
            <Badge variant="tag" className="capitalize">
              {run.attributes.trigger ?? "manual"}
            </Badge>
            {run.attributes.error_class ? (
              <Badge variant="tag" className="capitalize">
                {run.attributes.error_class.replaceAll("_", " ")}
              </Badge>
            ) : null}
            <span className="text-text-neutral-secondary text-sm">
              dry-run report
            </span>
          </div>
          <p className="text-text-neutral-secondary text-sm">
            Provider: {providerLabel}
            {run.attributes.provider_type
              ? ` (${run.attributes.provider_type})`
              : ""}
          </p>
          <p className="text-text-neutral-secondary text-sm">
            Resources matched: {resourceCount}
            {" · "}
            Duration: {duration}
            {run.attributes.summary?.regions?.length
              ? ` · Regions: ${run.attributes.summary.regions.join(", ")}`
              : ""}
          </p>
          {run.attributes.inserted_at ? (
            <p className="text-text-neutral-tertiary text-xs">
              {new Date(run.attributes.inserted_at).toLocaleString()}
            </p>
          ) : null}
          {run.attributes.error ? (
            <p className="text-text-error text-sm">
              {run.attributes.error_class
                ? `[${run.attributes.error_class}] `
                : ""}
              {run.attributes.error}
            </p>
          ) : null}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <CustodianDownloadYamlButton
            filename={`governance-policy-${policyId}.yml`}
            yaml={policy.attributes.policy_yaml}
          />
          {findingsHref ? (
            <Button asChild variant="ghost" size="sm">
              <Link href={findingsHref}>Related Findings</Link>
            </Button>
          ) : null}
          {isPending ? <CustodianCancelRunButton runId={runId} /> : null}
          <Button asChild variant="ghost" size="sm">
            <Link href={governanceHref(policyId)}>Back to policy</Link>
          </Button>
        </div>
      </div>

      <Section>
        <SectionHeader>
          <SectionTitle>Matched resources</SectionTitle>
          <SectionDescription>
            Findings-style detail — export CSV/JSON, compare deltas, and open a
            row for Overview / Metadata / Raw. Apply mode stays disabled.
          </SectionDescription>
        </SectionHeader>
        <SectionContent>
          <CustodianRunResourcesTable
            resources={resources}
            providerType={
              run.attributes.provider_type || policy.attributes.provider_type
            }
            delta={run.attributes.summary?.delta}
            prowlerCheckIds={prowlerCheckIds}
            runId={runId}
          />
        </SectionContent>
      </Section>
    </ContentLayout>
  );
}
