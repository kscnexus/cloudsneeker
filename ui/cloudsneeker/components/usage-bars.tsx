import {
  formatLimit,
  type LimitUsage,
  limitUsageNote,
  limitUsageRows,
} from "@/cloudsneeker/lib/entitlements";
import type { PlanLimits, UsageCounts } from "@/cloudsneeker/types/operator";
import { cn } from "@/lib/utils";

interface UsageBarsProps {
  usage: UsageCounts;
  limits: PlanLimits;
}

const USAGE_LEVEL = {
  OK: "ok",
  WARNING: "warning",
  OVER: "over",
} as const;

const usageLevel = (row: LimitUsage) =>
  row.over
    ? USAGE_LEVEL.OVER
    : row.warning
      ? USAGE_LEVEL.WARNING
      : USAGE_LEVEL.OK;

interface UsageNoteProps {
  row: LimitUsage;
}

const UsageNote = ({ row }: UsageNoteProps) => {
  const note = limitUsageNote(row);
  if (!note) return null;
  return (
    <p
      data-usage-note={usageLevel(row)}
      className={cn(
        "text-xs",
        row.over ? "text-text-error-primary" : "text-text-warning-primary",
      )}
    >
      {note}
    </p>
  );
};

/**
 * Usage against each plan limit; unlimited limits show the count only. A bar
 * warns from 80% of its limit and turns red above it.
 */
export const UsageBars = ({ usage, limits }: UsageBarsProps) => (
  <ul className="flex flex-col gap-3" aria-label="Usage against limits">
    {limitUsageRows(usage, limits).map((row) => (
      <li
        key={row.key}
        data-limit={row.key}
        data-usage-level={usageLevel(row)}
        className="flex flex-col gap-1"
      >
        <div className="flex items-center justify-between gap-2 text-sm">
          <span className="text-text-neutral-primary">{row.label}</span>
          <span
            className={cn(
              "tabular-nums",
              row.over
                ? "text-text-error-primary font-semibold"
                : "text-text-neutral-secondary",
            )}
          >
            {row.used === null
              ? "Not tracked"
              : row.used.toLocaleString("en-GB")}{" "}
            / {formatLimit(row.limit)}
          </span>
        </div>
        <div
          role="progressbar"
          aria-label={row.label}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={
            row.ratio === null ? undefined : Math.round(row.ratio * 100)
          }
          className="bg-bg-neutral-tertiary h-1.5 overflow-hidden rounded-full"
        >
          {row.ratio !== null ? (
            <div
              className={cn(
                "h-full rounded-full",
                row.over
                  ? "bg-bg-fail"
                  : row.warning
                    ? "bg-bg-warning"
                    : "bg-button-tertiary",
              )}
              style={{
                width: `${Math.max(row.ratio * 100, row.used ? 2 : 0)}%`,
              }}
            />
          ) : null}
        </div>
        <UsageNote row={row} />
      </li>
    ))}
  </ul>
);
