import { Shield } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import {
  getCustodianPolicy,
  listCustodianRuns,
} from "@/cloudsneeker/actions/custodian";
import { CustodianDryRunButton } from "@/cloudsneeker/components/custodian-dry-run-button";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { RunStatusBadge } from "@/cloudsneeker/components/run-status-badge";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { CARD_LIST_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { governanceHref } from "@/cloudsneeker/routes";
import type {
  CustodianPolicyResource,
  CustodianRunResource,
} from "@/cloudsneeker/types/custodian";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";

interface CustodianPolicyDetailPageProps {
  params: Promise<{ policyId: string }>;
}

export default async function CustodianPolicyDetailPage({
  params,
}: CustodianPolicyDetailPageProps) {
  const { policyId } = await params;
  const policyResponse = await getCustodianPolicy(policyId);

  if (
    !policyResponse ||
    ("error" in policyResponse && policyResponse.error) ||
    !policyResponse.data ||
    Array.isArray(policyResponse.data)
  ) {
    notFound();
  }

  const policy = policyResponse.data as CustodianPolicyResource;
  const runsResponse = await listCustodianRuns({
    "filter[policy]": policyId,
    "page[size]": "20",
    sort: "-inserted_at",
  });
  const runs = (runsResponse?.data ?? []) as CustodianRunResource[];

  return (
    <ContentLayout title={policy.attributes.name} icon={<Shield />}>
      <PageHeader
        description={policy.attributes.description || "No description"}
        meta={[
          {
            label: "Provider",
            value:
              policy.attributes.provider_alias ||
              policy.attributes.provider_uid ||
              policy.attributes.provider_id,
          },
          {
            label: "Schedule",
            value: policy.attributes.schedule_enabled
              ? `${policy.attributes.schedule_cron} (${policy.attributes.schedule_timezone || "UTC"})${
                  policy.attributes.next_run_at
                    ? ` · next ${new Date(policy.attributes.next_run_at).toLocaleString()}`
                    : ""
                }`
              : "Off",
          },
          { label: "Mode", value: "Dry-run only" },
        ]}
        actions={
          <>
            <Button asChild variant="ghost" size="sm">
              <Link href={governanceHref(policyId, "edit")}>Edit</Link>
            </Button>
            <CustodianDryRunButton policyId={policyId} />
          </>
        }
      >
        <p className="text-text-neutral-tertiary text-xs">
          Dry-run only — apply / remediate is not available.
        </p>
      </PageHeader>

      <div className="flex flex-col gap-6">
        <SectionCard
          title="Dry-run history"
          description="Newest first. Open a dry-run to see the resources it matched."
        >
          {runs.length === 0 ? (
            <p className="text-text-neutral-secondary text-sm">
              No dry-runs yet. Start one to see matching resources.
            </p>
          ) : (
            <ul className={CARD_LIST_CLASS}>
              {runs.map((run) => (
                <li key={run.id} className="flex flex-col gap-1.5 px-4 py-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <Link
                      href={governanceHref(policyId, "runs", run.id)}
                      className="text-text-neutral-primary rounded-sm text-sm font-medium underline-offset-2 hover:underline"
                    >
                      {run.attributes.inserted_at
                        ? new Date(run.attributes.inserted_at).toLocaleString()
                        : "Dry-run"}
                    </Link>
                    <RunStatusBadge status={run.attributes.status} />
                  </div>
                  <div className="text-text-neutral-secondary flex flex-wrap gap-x-3 gap-y-1 text-xs">
                    <span>mode: {run.attributes.mode}</span>
                    <span className="capitalize">
                      trigger: {run.attributes.trigger ?? "manual"}
                    </span>
                    <Link
                      href={governanceHref(policyId, "runs", run.id)}
                      className="rounded-sm underline-offset-2 hover:underline"
                    >
                      resources:{" "}
                      {run.attributes.summary?.resource_count ?? "—"}
                    </Link>
                    {run.attributes.summary?.regions?.length ? (
                      <span>
                        regions: {run.attributes.summary.regions.join(", ")}
                      </span>
                    ) : null}
                  </div>
                  {run.attributes.error ? (
                    <p className="text-text-error-primary text-xs break-all">
                      {run.attributes.error}
                    </p>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </SectionCard>

        <SectionCard title="Policy YAML">
          <pre className="bg-bg-neutral-tertiary overflow-x-auto rounded-lg p-4 text-sm">
            {policy.attributes.policy_yaml}
          </pre>
        </SectionCard>
      </div>
    </ContentLayout>
  );
}
