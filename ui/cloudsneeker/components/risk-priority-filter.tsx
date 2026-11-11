import Link from "next/link";

import {
  RISK_PRIORITY_INFO,
  RISK_PRIORITY_RULES,
} from "@/cloudsneeker/lib/app-security-priority";
import {
  type AreaFindingFilters,
  areaFindingsPageHref,
} from "@/cloudsneeker/lib/area-findings";
import {
  type FindingArea,
  RISK_PRIORITIES,
  type RiskPriority,
} from "@/cloudsneeker/types/area-findings";
import { cn } from "@/lib/utils";

interface RiskPriorityFilterProps {
  area: FindingArea;
  filters: AreaFindingFilters;
  counts: Partial<Record<RiskPriority, number>> | undefined;
  overdueCount: number | undefined;
  /** Name of the application in `filters.application`, when known. */
  applicationName?: string;
}

const chipClass = (active: boolean) =>
  cn(
    "inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors",
    active
      ? "border-button-primary bg-button-primary text-black"
      : "border-border-neutral-secondary text-text-neutral-secondary hover:text-text-neutral-primary",
  );

/** Priority and overdue chips with counts, plus the application filter. */
export const RiskPriorityFilter = ({
  area,
  filters,
  counts,
  overdueCount,
  applicationName,
}: RiskPriorityFilterProps) => {
  const reset = { ...filters, page: 1 };
  return (
    <div className="flex flex-col gap-2">
      <nav
        aria-label="Risk priority"
        title={RISK_PRIORITY_RULES}
        className="flex flex-wrap items-center gap-2"
      >
        {RISK_PRIORITIES.map((priority) => {
          const active = filters.priority === priority;
          const info = RISK_PRIORITY_INFO[priority];
          return (
            <Link
              key={priority}
              href={areaFindingsPageHref(area, {
                ...reset,
                priority: active ? undefined : priority,
              })}
              aria-current={active ? "true" : undefined}
              className={chipClass(active)}
            >
              {`${info.code} ${info.label}`}
              <span className="tabular-nums opacity-80">
                {counts?.[priority] ?? 0}
              </span>
            </Link>
          );
        })}
        <Link
          href={areaFindingsPageHref(area, {
            ...reset,
            overdue: filters.overdue ? undefined : true,
          })}
          aria-current={filters.overdue ? "true" : undefined}
          className={chipClass(Boolean(filters.overdue))}
        >
          Overdue
          <span className="tabular-nums opacity-80">{overdueCount ?? 0}</span>
        </Link>
      </nav>
      {filters.application ? (
        <p className="text-text-neutral-secondary flex flex-wrap items-center gap-2 text-xs">
          <span>
            Application:{" "}
            <span className="text-text-neutral-primary font-medium">
              {applicationName ?? filters.application}
            </span>
          </span>
          <Link
            href={areaFindingsPageHref(area, {
              ...reset,
              application: undefined,
            })}
            className="underline underline-offset-2"
          >
            Show every application
          </Link>
        </p>
      ) : null}
    </div>
  );
};
