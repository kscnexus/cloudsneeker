import { Shield } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { listCustodianPolicies } from "@/cloudsneeker/actions/custodian";
import { CustodianEmptyState } from "@/cloudsneeker/components/custodian-empty-state";
import type { CustodianPolicyResource } from "@/cloudsneeker/types/custodian";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";

export default function CustodianPage() {
  return (
    <ContentLayout title="Cloud Custodian" icon={<Shield />}>
      <div className="mb-4 flex items-center justify-between gap-4">
        <p className="text-text-neutral-secondary text-sm">
          Manage Cloud Custodian policies and dry-run them against connected AWS,
          Azure, GCP, or Kubernetes providers. Apply mode is disabled.
        </p>
        <Button asChild size="sm">
          <Link href="/custodian/new">Create policy</Link>
        </Button>
      </div>
      <Suspense fallback={<Skeleton className="h-40 w-full rounded-xl" />}>
        <SSRCustodianPolicyList />
      </Suspense>
    </ContentLayout>
  );
}

const SSRCustodianPolicyList = async () => {
  const response = await listCustodianPolicies({
    "page[size]": "50",
    sort: "-inserted_at",
  });

  if (response && "error" in response && response.error) {
    return (
      <p className="text-text-error text-sm">
        {typeof response.error === "string"
          ? response.error
          : "Unable to load Custodian policies."}
      </p>
    );
  }

  const policies = (response?.data ?? []) as CustodianPolicyResource[];

  if (policies.length === 0) {
    return <CustodianEmptyState />;
  }

  return (
    <ul className="divide-border-neutral-secondary border-border-neutral-secondary divide-y rounded-xl border">
      {policies.map((policy) => (
        <li key={policy.id}>
          <Link
            href={`/custodian/${policy.id}`}
            className="hover:bg-bg-neutral-secondary flex flex-col gap-1 px-4 py-3"
          >
            <span className="text-text-neutral-primary font-medium">
              {policy.attributes.name}
            </span>
            <span className="text-text-neutral-secondary text-sm">
              {policy.attributes.provider_alias ||
                policy.attributes.provider_uid ||
                policy.attributes.provider_id}
              {policy.attributes.description
                ? ` — ${policy.attributes.description}`
                : ""}
            </span>
            {policy.attributes.schedule_enabled ? (
              <span className="text-text-neutral-secondary text-xs">
                Schedule: {policy.attributes.schedule_cron} (
                {policy.attributes.schedule_timezone || "UTC"})
                {policy.attributes.next_run_at
                  ? ` · next ${new Date(policy.attributes.next_run_at).toLocaleString()}`
                  : ""}
              </span>
            ) : (
              <span className="text-text-neutral-secondary text-xs">
                Schedule: off
              </span>
            )}
          </Link>
        </li>
      ))}
    </ul>
  );
};
