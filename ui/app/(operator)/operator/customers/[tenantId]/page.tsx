import Link from "next/link";

import {
  getOperatorMe,
  getOperatorTenant,
  listPlans,
  listTenantUsageSnapshots,
} from "@/cloudsneeker/actions/operator";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { OperatorLoadError } from "@/cloudsneeker/components/operator-shell";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { SubscriptionEditor } from "@/cloudsneeker/components/subscription-editor";
import { SubscriptionHistory } from "@/cloudsneeker/components/subscription-history";
import { SubscriptionStatusBadge } from "@/cloudsneeker/components/subscription-status-badge";
import { UsageBars } from "@/cloudsneeker/components/usage-bars";
import {
  formatPlanDate,
  PLAN_FEATURE_LABEL,
} from "@/cloudsneeker/lib/entitlements";
import {
  isListResponse,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import {
  operatorCan,
  responseError,
  responseResource,
} from "@/cloudsneeker/lib/operator";
import { CARD_LIST_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { OPERATOR_ROUTE, operatorCustomerHref } from "@/cloudsneeker/routes";
import {
  OPERATOR_CAPABILITY,
  type OperatorMeAttributes,
  type OperatorTenantDetailAttributes,
  type PlanResource,
  type UsageSnapshotResource,
} from "@/cloudsneeker/types/operator";
import { Button } from "@/components/shadcn";

interface CustomerPageProps {
  params: Promise<{ tenantId: string }>;
}

const formatTime = (value: string | null): string =>
  value
    ? new Date(value).toLocaleString("en-GB", { timeZone: "UTC" })
    : "Never";

export default async function OperatorCustomerPage({
  params,
}: CustomerPageProps) {
  const { tenantId } = await params;
  const [tenantResponse, plansResponse, meResponse, usageResponse] =
    await Promise.all([
      getOperatorTenant(tenantId),
      listPlans(),
      getOperatorMe(),
      listTenantUsageSnapshots(tenantId, 30),
    ]);
  const tenant = responseResource<{
    id: string;
    attributes: OperatorTenantDetailAttributes;
  }>(tenantResponse);

  if (!tenant) {
    return (
      <>
        <PageHeader
          title="Customer"
          actions={
            <Button asChild size="sm" variant="outline">
              <Link href={OPERATOR_ROUTE.CUSTOMERS}>All customers</Link>
            </Button>
          }
        />
        <OperatorLoadError
          title="Customer unavailable"
          message={responseError(
            tenantResponse,
            "This customer could not be loaded.",
          )}
          retryHref={operatorCustomerHref(tenantId)}
        />
      </>
    );
  }

  const attributes = tenant.attributes;
  const me =
    responseResource<{ attributes: OperatorMeAttributes }>(meResponse)
      ?.attributes ?? null;
  const plans = responseList<PlanResource>(plansResponse).map((plan) => ({
    code: plan.attributes.code,
    name: plan.attributes.name,
  }));
  const canEdit =
    operatorCan(me, OPERATOR_CAPABILITY.MANAGE_SUBSCRIPTIONS) &&
    plans.length > 0;
  const snapshots = responseList<UsageSnapshotResource>(usageResponse);

  return (
    <>
      <PageHeader
        title={attributes.name}
        description={`Tenant ${tenant.id}`}
        actions={
          <Button asChild size="sm" variant="outline">
            <Link href={OPERATOR_ROUTE.CUSTOMERS}>All customers</Link>
          </Button>
        }
        meta={[
          { label: "Plan", value: attributes.plan_name },
          {
            label: "Status",
            value: (
              <SubscriptionStatusBadge status={attributes.effective_status} />
            ),
          },
          { label: "Ends", value: formatPlanDate(attributes.ends_at) },
          { label: "Members", value: attributes.member_count },
          {
            label: "Last activity",
            value: formatTime(attributes.last_activity),
          },
        ]}
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="flex min-w-0 flex-col gap-6 lg:col-span-2">
          {canEdit ? (
            <SubscriptionEditor
              tenantId={tenant.id}
              subscription={attributes.subscription}
              plans={plans}
              canSuspend={operatorCan(me, OPERATOR_CAPABILITY.SUSPEND_TENANTS)}
            />
          ) : (
            <SectionCard
              title="Subscription"
              description="Your operator role can view but not change subscriptions."
            >
              <p className="text-text-neutral-secondary text-sm">
                Features:{" "}
                {attributes.features
                  .map((feature) => PLAN_FEATURE_LABEL[feature] ?? feature)
                  .join(", ") || "None"}
              </p>
            </SectionCard>
          )}
        </div>
        <div className="flex min-w-0 flex-col gap-6">
          <SectionCard title="Usage against limits">
            <UsageBars usage={attributes.usage} limits={attributes.limits} />
          </SectionCard>
          <SectionCard
            title="Daily usage"
            description="Last 30 days, newest first."
          >
            {!isListResponse(usageResponse) ? (
              <OperatorLoadError
                title="Usage history unavailable"
                message={responseError(
                  usageResponse,
                  "Snapshots could not be loaded.",
                )}
                retryHref={operatorCustomerHref(tenant.id)}
              />
            ) : snapshots.length === 0 ? (
              <EmptyState
                title="No snapshots yet"
                description="The daily usage task writes one per day."
              />
            ) : (
              <ul className={CARD_LIST_CLASS} aria-label="Daily usage">
                {snapshots.slice(0, 30).map((snapshot) => (
                  <li
                    key={snapshot.id}
                    className="flex items-center justify-between gap-2 px-3 py-2 text-xs"
                  >
                    <span className="text-text-neutral-primary">
                      {snapshot.attributes.date}
                    </span>
                    <span className="text-text-neutral-secondary tabular-nums">
                      {snapshot.attributes.counts.providers ?? 0} providers ·{" "}
                      {snapshot.attributes.counts.users ?? 0} users ·{" "}
                      {snapshot.attributes.counts.scans_this_month ?? 0} scans
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </SectionCard>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <SectionCard title="Members">
          {attributes.members.length === 0 ? (
            <EmptyState title="No members" />
          ) : (
            <ul className={CARD_LIST_CLASS} aria-label="Members">
              {attributes.members.map((member) => (
                <li
                  key={member.user_id}
                  className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-sm"
                >
                  <span className="text-text-neutral-primary min-w-0 truncate">
                    {member.email}
                  </span>
                  <span className="text-text-neutral-tertiary text-xs">
                    {member.role} · last sign-in {formatTime(member.last_login)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </SectionCard>
        <SectionCard title="Recent scans">
          {attributes.recent_scans.length === 0 ? (
            <EmptyState title="No scans yet" />
          ) : (
            <ul className={CARD_LIST_CLASS} aria-label="Recent scans">
              {attributes.recent_scans.map((scan) => (
                <li
                  key={scan.id}
                  className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-sm"
                >
                  <span className="text-text-neutral-primary min-w-0 truncate">
                    {scan.name || scan.id.slice(0, 8)}
                  </span>
                  <span className="text-text-neutral-tertiary text-xs">
                    {scan.state} · {formatTime(scan.inserted_at)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </SectionCard>
      </div>

      <SectionCard title="Subscription history">
        {attributes.history.length === 0 ? (
          <EmptyState title="No changes recorded" />
        ) : (
          <SubscriptionHistory events={attributes.history} />
        )}
      </SectionCard>
    </>
  );
}
