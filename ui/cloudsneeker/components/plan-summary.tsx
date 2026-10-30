import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  formatLimit,
  formatPlanDate,
  limitUsageRows,
  SUBSCRIPTION_STATUS_LABEL,
} from "@/cloudsneeker/lib/entitlements";
import type { EntitlementsAttributes } from "@/cloudsneeker/types/operator";

export const PlanSummary = ({
  entitlements,
}: {
  entitlements: EntitlementsAttributes;
}) => {
  const status =
    SUBSCRIPTION_STATUS_LABEL[entitlements.effective_status] ??
    entitlements.effective_status;
  const limited = limitUsageRows(
    entitlements.usage,
    entitlements.limits,
  ).filter((row) => row.limit !== null);
  return (
    <SectionCard
      title="Plan"
      description="Your organization's subscription. Contact your account manager to change it."
    >
      <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-3">
        <div className="flex flex-col gap-0.5">
          <dt className="text-text-neutral-tertiary text-xs font-medium tracking-wide uppercase">
            Plan
          </dt>
          <dd className="text-text-neutral-primary font-medium">
            {entitlements.plan.name}
          </dd>
        </div>
        <div className="flex flex-col gap-0.5">
          <dt className="text-text-neutral-tertiary text-xs font-medium tracking-wide uppercase">
            Status
          </dt>
          <dd className="text-text-neutral-primary">{status}</dd>
        </div>
        <div className="flex flex-col gap-0.5">
          <dt className="text-text-neutral-tertiary text-xs font-medium tracking-wide uppercase">
            Renews or ends
          </dt>
          <dd className="text-text-neutral-primary">
            {formatPlanDate(
              entitlements.effective_status === "trial"
                ? (entitlements.trial_ends_at ?? entitlements.ends_at)
                : entitlements.ends_at,
            )}
          </dd>
        </div>
      </dl>
      {limited.length > 0 ? (
        <ul className="text-text-neutral-secondary flex flex-wrap gap-x-6 gap-y-1 text-xs">
          {limited.map((row) => (
            <li key={row.key}>
              {row.label}: {row.used ?? 0} of {formatLimit(row.limit)}
            </li>
          ))}
        </ul>
      ) : null}
    </SectionCard>
  );
};
