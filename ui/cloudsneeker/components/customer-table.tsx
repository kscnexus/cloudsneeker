import Link from "next/link";

import { SubscriptionStatusBadge } from "@/cloudsneeker/components/subscription-status-badge";
import {
  formatLimit,
  formatPlanDate,
  PLAN_LIMIT_LABEL,
} from "@/cloudsneeker/lib/entitlements";
import { FOCUS_RING_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { operatorCustomerHref } from "@/cloudsneeker/routes";
import type { OperatorTenantResource } from "@/cloudsneeker/types/operator";
import { cn } from "@/lib/utils";

export const CUSTOMER_TABLE_COLUMNS = [
  "Customer",
  "Plan",
  "Status",
  "Ends",
  "Members",
  "Providers",
  "Last activity",
] as const;

const formatActivity = (value: string | null): string =>
  value
    ? new Date(value).toLocaleString("en-GB", {
        day: "numeric",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        timeZone: "UTC",
      })
    : "None";

export const CustomerTable = ({
  tenants,
}: {
  tenants: OperatorTenantResource[];
}) => (
  <div className="border-border-neutral-secondary overflow-x-auto rounded-xl border">
    <table className="w-full text-left text-sm">
      <thead className="bg-bg-neutral-tertiary">
        <tr>
          {CUSTOMER_TABLE_COLUMNS.map((header) => (
            <th
              key={header}
              scope="col"
              className="text-text-neutral-secondary px-3 py-2 text-xs font-semibold whitespace-nowrap"
            >
              {header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody className="divide-border-neutral-secondary divide-y">
        {tenants.map((tenant) => {
          const attributes = tenant.attributes;
          const over = attributes.over_limit.length > 0;
          return (
            <tr key={tenant.id} data-testid="customer-row">
              <td className="max-w-64 px-3 py-2">
                <Link
                  href={operatorCustomerHref(tenant.id)}
                  className={cn(
                    "text-text-neutral-primary block truncate font-medium hover:underline",
                    FOCUS_RING_CLASS,
                  )}
                >
                  {attributes.name}
                </Link>
                {over ? (
                  <span className="text-text-error-primary text-xs">
                    Over limit:{" "}
                    {attributes.over_limit
                      .map((key) => PLAN_LIMIT_LABEL[key] ?? key)
                      .join(", ")}
                  </span>
                ) : null}
              </td>
              <td className="text-text-neutral-primary px-3 py-2 whitespace-nowrap">
                {attributes.plan_name}
              </td>
              <td className="px-3 py-2">
                <SubscriptionStatusBadge status={attributes.effective_status} />
              </td>
              <td className="text-text-neutral-secondary px-3 py-2 whitespace-nowrap">
                {formatPlanDate(attributes.ends_at)}
              </td>
              <td className="text-text-neutral-secondary px-3 py-2 tabular-nums">
                {attributes.member_count}
              </td>
              <td className="text-text-neutral-secondary px-3 py-2 whitespace-nowrap tabular-nums">
                {attributes.usage.providers ?? 0} /{" "}
                {formatLimit(attributes.limits.providers)}
              </td>
              <td className="text-text-neutral-secondary px-3 py-2 text-xs whitespace-nowrap">
                {formatActivity(attributes.last_activity)}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);
