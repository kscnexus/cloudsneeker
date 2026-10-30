import Link from "next/link";

import { operatorCustomerHref } from "@/cloudsneeker/routes";
import type { OperatorAuditResource } from "@/cloudsneeker/types/operator";

export const OPERATOR_AUDIT_COLUMNS = [
  "Time",
  "Operator",
  "Action",
  "Customer",
  "Fields changed",
  "IP address",
] as const;

const ACTION_LABEL: Record<string, string> = {
  "subscription.update": "Subscription changed",
  "plan.create": "Plan created",
  "plan.update": "Plan changed",
  "plan.delete": "Plan deleted",
  "operator.grant": "Operator granted",
  "operator.revoke": "Operator revoked",
};

export const operatorActionLabel = (action: string): string =>
  ACTION_LABEL[action] ?? action;

export const OperatorAuditTable = ({
  events,
}: {
  events: OperatorAuditResource[];
}) => (
  <div className="border-border-neutral-secondary overflow-x-auto rounded-xl border">
    <table className="w-full text-left text-sm">
      <thead className="bg-bg-neutral-tertiary">
        <tr>
          {OPERATOR_AUDIT_COLUMNS.map((header) => (
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
        {events.map((event) => {
          const attributes = event.attributes;
          const rawTenantName = attributes.metadata?.tenant_name;
          const tenantName =
            typeof rawTenantName === "string" ? rawTenantName : null;
          return (
            <tr key={event.id} data-testid="operator-audit-row">
              <td className="text-text-neutral-secondary px-3 py-2 text-xs whitespace-nowrap">
                {attributes.inserted_at
                  ? new Date(attributes.inserted_at).toLocaleString("en-GB", {
                      timeZone: "UTC",
                    })
                  : ""}
              </td>
              <td className="text-text-neutral-primary max-w-56 truncate px-3 py-2">
                {attributes.actor_email || "Unknown"}
                {attributes.actor_role ? (
                  <span className="text-text-neutral-tertiary ml-1 text-xs">
                    ({attributes.actor_role})
                  </span>
                ) : null}
              </td>
              <td className="text-text-neutral-primary px-3 py-2 whitespace-nowrap">
                {operatorActionLabel(attributes.action)}
                {attributes.target_type === "plan" && attributes.target_id ? (
                  <span className="text-text-neutral-tertiary ml-1 text-xs">
                    {attributes.target_id}
                  </span>
                ) : null}
              </td>
              <td className="px-3 py-2">
                {attributes.tenant_id ? (
                  <Link
                    href={operatorCustomerHref(attributes.tenant_id)}
                    className="text-text-neutral-primary hover:underline"
                  >
                    {tenantName ?? attributes.tenant_id.slice(0, 8)}
                  </Link>
                ) : (
                  <span className="text-text-neutral-tertiary">—</span>
                )}
              </td>
              <td className="text-text-neutral-secondary px-3 py-2 text-xs">
                {attributes.changed_fields.length > 0
                  ? attributes.changed_fields.join(", ")
                  : "—"}
              </td>
              <td className="text-text-neutral-secondary px-3 py-2 text-xs whitespace-nowrap">
                {attributes.ip_address ?? "—"}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);
