import Link from "next/link";

import { listOperatorTenants } from "@/cloudsneeker/actions/operator";
import { CustomerTable } from "@/cloudsneeker/components/customer-table";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { OperatorLoadError } from "@/cloudsneeker/components/operator-shell";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { STAT_TILE_TONE, StatTile } from "@/cloudsneeker/components/stat-tile";
import { SUBSCRIPTION_STATUS_LABEL } from "@/cloudsneeker/lib/entitlements";
import {
  isListResponse,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import {
  responseError,
  statusTone,
  summaryFromMeta,
} from "@/cloudsneeker/lib/operator";
import { OPERATOR_ROUTE } from "@/cloudsneeker/routes";
import type {
  OperatorTenantResource,
  SubscriptionStatus,
} from "@/cloudsneeker/types/operator";
import { Button } from "@/components/shadcn";

const PREVIEW_SIZE = "10";

export default async function OperatorOverviewPage() {
  const [all, expiring, overLimit] = await Promise.all([
    listOperatorTenants({ "page[size]": "1" }),
    listOperatorTenants({
      "filter[expiring_within_days]": "30",
      sort: "ends_at",
      "page[size]": PREVIEW_SIZE,
    }),
    listOperatorTenants({
      "filter[over_limit]": "true",
      "page[size]": PREVIEW_SIZE,
    }),
  ]);
  const summary = summaryFromMeta(all);

  if (!summary) {
    return (
      <>
        <PageHeader title="Overview" />
        <OperatorLoadError
          title="Overview unavailable"
          message={responseError(all, "Customers could not be loaded.")}
          retryHref={OPERATOR_ROUTE.OVERVIEW}
        />
      </>
    );
  }

  const statuses = Object.entries(summary.by_status).sort(
    (a, b) => b[1] - a[1],
  );
  const plans = Object.entries(summary.by_plan).sort((a, b) => b[1] - a[1]);

  return (
    <>
      <PageHeader
        title="Overview"
        description="Customers by subscription status, plan distribution, plans ending in the next 30 days, and customers above a plan limit."
        actions={
          <Button asChild size="sm" variant="outline">
            <Link href={OPERATOR_ROUTE.CUSTOMERS}>All customers</Link>
          </Button>
        }
      />
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile
          label="Customers"
          value={summary.total}
          tone={STAT_TILE_TONE.ACCENT}
        />
        <StatTile
          label="Ending within 30 days"
          value={summary.expiring_within_30_days}
          tone={
            summary.expiring_within_30_days > 0
              ? STAT_TILE_TONE.WARNING
              : STAT_TILE_TONE.SUCCESS
          }
          href={`${OPERATOR_ROUTE.CUSTOMERS}?expiring=30`}
        />
        <StatTile
          label="Over a limit"
          value={summary.over_limit}
          tone={
            summary.over_limit > 0
              ? STAT_TILE_TONE.DANGER
              : STAT_TILE_TONE.SUCCESS
          }
          href={`${OPERATOR_ROUTE.CUSTOMERS}?over_limit=true`}
        />
        <StatTile
          label="Read-only"
          value={
            (summary.by_status.suspended ?? 0) +
            (summary.by_status.expired ?? 0) +
            (summary.by_status.cancelled ?? 0)
          }
          tone={STAT_TILE_TONE.NEUTRAL}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <SectionCard title="By status">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            {statuses.map(([status, count]) => (
              <StatTile
                key={status}
                label={
                  SUBSCRIPTION_STATUS_LABEL[status as SubscriptionStatus] ??
                  status
                }
                value={count}
                tone={statusTone(status as SubscriptionStatus)}
                href={`${OPERATOR_ROUTE.CUSTOMERS}?status=${encodeURIComponent(status)}`}
              />
            ))}
          </div>
        </SectionCard>
        <SectionCard title="Plan distribution">
          <ul
            className="flex flex-col gap-2 text-sm"
            aria-label="Customers per plan"
          >
            {plans.map(([plan, count]) => (
              <li key={plan} className="flex items-center gap-3">
                <Link
                  href={`${OPERATOR_ROUTE.CUSTOMERS}?plan=${encodeURIComponent(plan)}`}
                  className="text-text-neutral-primary w-32 shrink-0 truncate hover:underline"
                >
                  {plan}
                </Link>
                <div className="bg-bg-neutral-tertiary h-2 flex-1 overflow-hidden rounded-full">
                  <div
                    className="bg-button-tertiary h-full rounded-full"
                    style={{
                      width: `${summary.total ? (count / summary.total) * 100 : 0}%`,
                    }}
                  />
                </div>
                <span className="text-text-neutral-secondary w-10 text-right tabular-nums">
                  {count}
                </span>
              </li>
            ))}
          </ul>
        </SectionCard>
      </div>

      <TenantPreview
        title="Ending within 30 days"
        response={expiring}
        emptyTitle="Nothing ends in the next 30 days"
      />
      <TenantPreview
        title="Over a plan limit"
        response={overLimit}
        emptyTitle="No customer is above a limit"
      />
    </>
  );
}

const TenantPreview = ({
  title,
  response,
  emptyTitle,
}: {
  title: string;
  response: unknown;
  emptyTitle: string;
}) => {
  if (!isListResponse(response)) {
    return (
      <SectionCard title={title}>
        <OperatorLoadError
          title={`${title}: unavailable`}
          message={responseError(response, "This list could not be loaded.")}
          retryHref={OPERATOR_ROUTE.OVERVIEW}
        />
      </SectionCard>
    );
  }
  const tenants = responseList<OperatorTenantResource>(response);
  return (
    <SectionCard title={title}>
      {tenants.length === 0 ? (
        <EmptyState title={emptyTitle} />
      ) : (
        <CustomerTable tenants={tenants} />
      )}
    </SectionCard>
  );
};
