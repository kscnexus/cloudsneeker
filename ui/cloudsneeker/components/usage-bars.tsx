import { formatLimit, limitUsageRows } from "@/cloudsneeker/lib/entitlements";
import type { PlanLimits, UsageCounts } from "@/cloudsneeker/types/operator";
import { cn } from "@/lib/utils";

interface UsageBarsProps {
  usage: UsageCounts;
  limits: PlanLimits;
}

/** Usage against each plan limit; unlimited limits show the count only. */
export const UsageBars = ({ usage, limits }: UsageBarsProps) => (
  <ul className="flex flex-col gap-3" aria-label="Usage against limits">
    {limitUsageRows(usage, limits).map((row) => (
      <li key={row.key} data-limit={row.key} className="flex flex-col gap-1">
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
                  : row.ratio >= 0.8
                    ? "bg-bg-warning"
                    : "bg-button-tertiary",
              )}
              style={{
                width: `${Math.max(row.ratio * 100, row.used ? 2 : 0)}%`,
              }}
            />
          ) : null}
        </div>
      </li>
    ))}
  </ul>
);
