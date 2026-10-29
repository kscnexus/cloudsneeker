import Link from "next/link";

import { SEVERITY_LABEL } from "@/cloudsneeker/lib/report-view";
import { FOCUS_RING_CLASS } from "@/cloudsneeker/lib/ui-classes";
import type { ReportSeverity } from "@/cloudsneeker/types/reports";
import { cn } from "@/lib/utils";

export const SEVERITY_FILL_CLASS: Record<ReportSeverity, string> = {
  critical: "bg-bg-data-critical",
  high: "bg-bg-data-high",
  medium: "bg-bg-data-medium",
  low: "bg-bg-data-low",
  informational: "bg-bg-data-info",
};

export interface SeverityBreakdownItem {
  severity: ReportSeverity;
  count: number;
  /** Findings drill-down for this severity. */
  href?: string;
}

interface SeverityBreakdownProps {
  items: SeverityBreakdownItem[];
  /** Accessible name for the proportion bar. */
  label?: string;
  className?: string;
}

export const SeverityBreakdown = ({
  items,
  label = "Open findings by severity",
  className,
}: SeverityBreakdownProps) => {
  const total = items.reduce((sum, item) => sum + item.count, 0);
  const summary = items
    .map((item) => `${SEVERITY_LABEL[item.severity]} ${item.count}`)
    .join(", ");

  return (
    <div className={cn("flex flex-col gap-3", className)}>
      <div
        role="img"
        aria-label={`${label}: ${total === 0 ? "none" : summary}`}
        className="bg-bg-neutral-tertiary flex h-2.5 w-full overflow-hidden rounded-full"
      >
        {total > 0
          ? items
              .filter((item) => item.count > 0)
              .map((item) => (
                <span
                  key={item.severity}
                  className={cn("h-full", SEVERITY_FILL_CLASS[item.severity])}
                  style={{ width: `${(item.count / total) * 100}%` }}
                />
              ))
          : null}
      </div>
      <ul className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
        {items.map((item) => {
          const content = (
            <>
              <span className="flex items-center gap-1.5">
                <span
                  aria-hidden="true"
                  className={cn(
                    "size-2 shrink-0 rounded-full",
                    SEVERITY_FILL_CLASS[item.severity],
                  )}
                />
                <span className="text-text-neutral-secondary text-xs">
                  {SEVERITY_LABEL[item.severity]}
                </span>
              </span>
              <span className="text-text-neutral-primary text-lg font-semibold tabular-nums">
                {item.count.toLocaleString("en-US")}
              </span>
            </>
          );
          return (
            <li key={item.severity} className="min-w-0">
              {item.href ? (
                <Link
                  href={item.href}
                  className={cn(
                    "border-border-neutral-secondary hover:bg-bg-neutral-tertiary flex flex-col gap-0.5 rounded-lg border px-3 py-2 transition-colors",
                    FOCUS_RING_CLASS,
                  )}
                >
                  {content}
                </Link>
              ) : (
                <div className="border-border-neutral-secondary flex flex-col gap-0.5 rounded-lg border px-3 py-2">
                  {content}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
};
