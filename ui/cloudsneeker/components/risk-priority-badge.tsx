import {
  isRiskPriority,
  RISK_PRIORITY_INFO,
} from "@/cloudsneeker/lib/app-security-priority";
import { cn } from "@/lib/utils";

/** "P1 Urgent" pill; a dash when the finding has no priority. */
export const RiskPriorityBadge = ({
  priority,
  overdue = false,
}: {
  priority: string | undefined;
  overdue?: boolean;
}) => {
  if (!priority || !isRiskPriority(priority)) {
    return <span className="text-text-neutral-tertiary text-xs">—</span>;
  }
  const info = RISK_PRIORITY_INFO[priority];
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <span
        title={`${info.code} ${info.label}: fix within ${info.slaDays} days of first seen`}
        className={cn(
          "inline-flex rounded-full border px-2 py-0.5 text-xs font-semibold whitespace-nowrap",
          info.className,
        )}
      >
        {`${info.code} ${info.label}`}
      </span>
      {overdue ? (
        <span className="text-text-error-primary text-xs font-medium whitespace-nowrap">
          Overdue
        </span>
      ) : null}
    </span>
  );
};
