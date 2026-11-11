import Link from "next/link";

import { CustodianEmptyState } from "@/cloudsneeker/components/custodian-empty-state";
import { governanceHref } from "@/cloudsneeker/routes";
import type { CustodianPolicyResource } from "@/cloudsneeker/types/custodian";

interface CustodianPolicyListProps {
  policies: CustodianPolicyResource[];
  /** Filters are active: an empty list means no match, not no policies. */
  filtered?: boolean;
}

export const CustodianPolicyList = ({
  policies,
  filtered = false,
}: CustodianPolicyListProps) => {
  if (policies.length === 0) {
    return filtered ? (
      <p className="text-text-neutral-secondary text-sm">
        No policies match these filters. Clear them to see every policy.
      </p>
    ) : (
      <CustodianEmptyState />
    );
  }

  return (
    <ul className="divide-border-neutral-secondary border-border-neutral-secondary divide-y rounded-xl border">
      {policies.map((policy) => (
        <li key={policy.id}>
          <Link
            href={governanceHref(policy.id)}
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
