import { Shield } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import {
  getCustodianPolicy,
  listCustodianRuns,
} from "@/cloudsneeker/actions/custodian";
import { CustodianDryRunButton } from "@/cloudsneeker/components/custodian-dry-run-button";
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
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="flex max-w-2xl flex-col gap-1">
          <p className="text-text-neutral-secondary text-sm">
            {policy.attributes.description || "No description"}
          </p>
          <p className="text-text-neutral-secondary text-sm">
            Provider:{" "}
            {policy.attributes.provider_alias ||
              policy.attributes.provider_uid ||
              policy.attributes.provider_id}
          </p>
          <p className="text-text-neutral-secondary text-xs">
            Dry-run only — apply / remediate is not available.
          </p>
          {policy.attributes.schedule_enabled ? (
            <p className="text-text-neutral-secondary text-sm">
              Schedule: {policy.attributes.schedule_cron} (
              {policy.attributes.schedule_timezone || "UTC"})
              {policy.attributes.next_run_at
                ? ` · next ${new Date(policy.attributes.next_run_at).toLocaleString()}`
                : ""}
            </p>
          ) : (
            <p className="text-text-neutral-secondary text-sm">
              Schedule: off
            </p>
          )}
        </div>
        <div className="flex gap-2">
          <Button asChild variant="ghost" size="sm">
            <Link href={`/custodian/${policyId}/edit`}>Edit</Link>
          </Button>
          <CustodianDryRunButton policyId={policyId} />
        </div>
      </div>

      <section className="mb-8 flex flex-col gap-2">
        <h2 className="text-text-neutral-primary text-base font-semibold">
          Policy YAML
        </h2>
        <pre className="border-border-neutral-secondary bg-bg-neutral-secondary overflow-x-auto rounded-xl border p-4 text-sm">
          {policy.attributes.policy_yaml}
        </pre>
      </section>

      <section className="flex flex-col gap-3">
        <h2 className="text-text-neutral-primary text-base font-semibold">
          Dry-run history
        </h2>
        {runs.length === 0 ? (
          <p className="text-text-neutral-secondary text-sm">
            No dry-runs yet. Start one to see matching resources.
          </p>
        ) : (
          <ul className="divide-border-neutral-secondary border-border-neutral-secondary divide-y rounded-xl border">
            {runs.map((run) => (
              <li key={run.id} className="flex flex-col gap-1 px-4 py-3">
                <div className="flex flex-wrap items-center gap-3 text-sm">
                  <Link
                    href={`/custodian/${policyId}/runs/${run.id}`}
                    className="text-text-neutral-primary font-medium capitalize hover:underline"
                  >
                    {run.attributes.status}
                  </Link>
                  <span className="text-text-neutral-secondary">
                    mode: {run.attributes.mode}
                  </span>
                  <span className="text-text-neutral-secondary capitalize">
                    trigger: {run.attributes.trigger ?? "manual"}
                  </span>
                  <Link
                    href={`/custodian/${policyId}/runs/${run.id}`}
                    className="text-text-neutral-secondary hover:underline"
                  >
                    resources:{" "}
                    {run.attributes.summary?.resource_count ?? "—"}
                  </Link>
                  {run.attributes.summary?.regions?.length ? (
                    <span className="text-text-neutral-secondary">
                      regions: {run.attributes.summary.regions.join(", ")}
                    </span>
                  ) : null}
                </div>
                {run.attributes.error ? (
                  <p className="text-text-error text-sm">
                    {run.attributes.error}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </section>
    </ContentLayout>
  );
}
