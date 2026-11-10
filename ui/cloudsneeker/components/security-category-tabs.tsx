import Link from "next/link";

import {
  categoryTotal,
  NOT_INTEGRATED_CATEGORIES,
  SECURITY_CATEGORY_INFO,
  type SecurityCategoryTab,
} from "@/cloudsneeker/lib/app-security-categories";
import {
  type AreaFindingFilters,
  areaFindingsPageHref,
} from "@/cloudsneeker/lib/area-findings";
import type { FindingArea } from "@/cloudsneeker/types/area-findings";
import { cn } from "@/lib/utils";

interface SecurityCategoryTabsProps {
  area: FindingArea;
  filters: AreaFindingFilters;
  tabs: SecurityCategoryTab[];
}

const tabClass = (active: boolean, enabled: boolean) =>
  cn(
    "flex min-w-28 flex-col gap-0.5 rounded-lg border px-3 py-2 text-left transition-colors",
    active
      ? "border-button-primary bg-bg-neutral-tertiary"
      : "border-border-neutral-secondary hover:border-border-neutral-primary",
    !enabled && "opacity-60",
  );

const TabBody = ({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint?: string;
}) => (
  <>
    <span className="text-text-neutral-secondary text-xs font-medium">
      {label}
    </span>
    <span className="text-text-neutral-primary text-lg font-semibold tabular-nums">
      {value}
    </span>
    {hint ? (
      <span className="text-text-neutral-tertiary text-[11px]">{hint}</span>
    ) : null}
  </>
);

/** Category tabs: every finding sits in exactly one, so they add up to All. */
export const SecurityCategoryTabs = ({
  area,
  filters,
  tabs,
}: SecurityCategoryTabsProps) => {
  const reset = { ...filters, page: 1, category: undefined };
  return (
    <div className="flex flex-col gap-2">
      <nav
        aria-label="Security category"
        className="flex gap-2 overflow-x-auto pb-1"
      >
        <Link
          href={areaFindingsPageHref(area, reset)}
          aria-current={filters.category ? undefined : "page"}
          className={tabClass(!filters.category, true)}
        >
          <TabBody label="All categories" value={String(categoryTotal(tabs))} />
        </Link>
        {tabs.map((tab) => {
          const active = filters.category === tab.category;
          const info = SECURITY_CATEGORY_INFO[tab.category];
          if (!tab.enabled) {
            return (
              <div
                key={tab.category}
                title={`${info.label}: no target runs this scan type yet.`}
                className={tabClass(false, false)}
              >
                <TabBody label={tab.label} value="—" hint="Not enabled" />
              </div>
            );
          }
          return (
            <Link
              key={tab.category}
              href={areaFindingsPageHref(area, {
                ...reset,
                category: tab.category,
              })}
              aria-current={active ? "page" : undefined}
              title={`${info.label}. ${info.description}`}
              className={tabClass(active, true)}
            >
              <TabBody label={tab.label} value={String(tab.count)} />
            </Link>
          );
        })}
      </nav>
      <p className="text-text-neutral-tertiary text-xs">
        {`Not integrated: ${NOT_INTEGRATED_CATEGORIES.join(", ")}.`}
      </p>
    </div>
  );
};
