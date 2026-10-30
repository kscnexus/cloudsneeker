import {
  auditActionLabel,
  auditOutcomeLabel,
  auditOutcomeVariant,
  auditTargetTypeLabel,
  formatAuditTime,
  shortId,
} from "@/cloudsneeker/lib/audit-log";
import type { AuditEventResource } from "@/cloudsneeker/types/audit";
import { Badge } from "@/components/shadcn";

export const AUDIT_LOG_COLUMNS = [
  "Time",
  "Actor",
  "Action",
  "Target",
  "Outcome",
  "IP address",
] as const;

const targetText = (event: AuditEventResource): string => {
  const { target_type, target_id, target_label } = event.attributes;
  if (!target_type && !target_id) return "—";
  const type = target_type ? auditTargetTypeLabel(target_type) : "";
  const name = target_label || (target_id ? shortId(target_id) : "");
  return [type, name].filter(Boolean).join(" · ");
};

interface AuditLogTableProps {
  events: AuditEventResource[];
}

export const AuditLogTable = ({ events }: AuditLogTableProps) => (
  <div className="border-border-neutral-secondary overflow-x-auto rounded-xl border">
    <table className="w-full text-left text-sm">
      <thead className="bg-bg-neutral-tertiary">
        <tr>
          {AUDIT_LOG_COLUMNS.map((header) => (
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
          return (
            <tr key={event.id} data-testid="audit-log-row">
              <td className="text-text-neutral-secondary px-3 py-2 text-xs whitespace-nowrap">
                <time dateTime={attributes.inserted_at}>
                  {formatAuditTime(attributes.inserted_at)}
                </time>
              </td>
              <td className="text-text-neutral-primary max-w-56 truncate px-3 py-2">
                {attributes.actor_email || "Unknown"}
              </td>
              <td className="text-text-neutral-primary px-3 py-2">
                {auditActionLabel(attributes.action)}
              </td>
              <td className="text-text-neutral-secondary max-w-72 truncate px-3 py-2">
                {targetText(event)}
              </td>
              <td className="px-3 py-2">
                <Badge variant={auditOutcomeVariant(attributes.outcome)}>
                  {auditOutcomeLabel(attributes.outcome)}
                </Badge>
              </td>
              <td className="text-text-neutral-secondary px-3 py-2 font-mono text-xs whitespace-nowrap">
                {attributes.ip_address || "—"}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);
