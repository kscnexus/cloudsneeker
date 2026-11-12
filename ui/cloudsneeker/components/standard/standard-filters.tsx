"use client";

import { ChevronDown } from "lucide-react";
import type { ReactNode } from "react";
import { useState } from "react";

import { ApplyFiltersButton } from "@/components/filters/apply-filters-button";
import { BatchFiltersLayout } from "@/components/filters/batch-filters-layout";
import { ClearFiltersButton } from "@/components/filters/clear-filters-button";
import { CustomDatePicker } from "@/components/filters/custom-date-picker";
import {
  type FilterChip,
  FilterSummaryStrip,
} from "@/components/filters/filter-summary-strip";
import { Button } from "@/components/shadcn";
import { ExpandableSection } from "@/components/shadcn/expandable-section";
import { DataTableFilterCustom } from "@/components/shadcn/table/data-table-filter-custom";
import { useFilterBatch } from "@/hooks/use-filter-batch";
import { DATA_TABLE_FILTER_MODE, type FilterOption } from "@/types/filters";

import {
  buildStandardChips,
  type StandardFilter,
  toFilterOption,
} from "./standard-filters.utils";

interface StandardFiltersProps {
  /** Prefix of the layout's test ids, e.g. "governance-findings". */
  testIdPrefix: string;
  /** Dropdowns in display order; values are plain data (server-safe). */
  filters: StandardFilter[];
  /** Dropdowns shown in the first row; the rest open under "More Filters". */
  primaryCount?: number;
  /** `filter[...]` key of a date filter shown under "More Filters". */
  dateKey?: string;
  /** Parameters kept when filters are applied or cleared. */
  defaultParams?: Record<string, string>;
  /** Extra controls after the dropdowns (for example a search box). */
  trailingControls?: ReactNode;
}

const FILTER_GRID_CLASS =
  "w-full gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5";

/**
 * The Cloud Security Findings filter bar for any list: searchable
 * multi-selects with Select All, changes staged until Apply, removable chips
 * for what is applied, Clear Filters, and "More Filters" for the rest. State
 * lives in the URL (`filter[...]`), so paging and navigation keep it.
 */
export const StandardFilters = ({
  testIdPrefix,
  filters,
  primaryCount = 4,
  dateKey,
  defaultParams,
  trailingControls,
}: StandardFiltersProps) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const {
    appliedFilters,
    pendingFilters,
    changedFilters,
    setPending,
    applyAll,
    discardAll,
    clearAndApply,
    removeAppliedAndApply,
    hasChanges,
    changeCount,
    getFilterValue,
  } = useFilterBatch({ defaultParams });

  const options: FilterOption[] = filters.map((filter, index) => ({
    ...toFilterOption(filter),
    index,
  }));
  const primary = options.slice(0, primaryCount);
  const more = options.slice(primaryCount);
  const hasMore = more.length > 0 || Boolean(dateKey);

  const appliedChips: FilterChip[] = buildStandardChips(
    appliedFilters,
    filters,
  );
  const pendingChips: FilterChip[] = buildStandardChips(
    changedFilters,
    filters,
  );
  const appliedCount = appliedChips.length;

  const removePendingChip = (filterKey: string, value?: string) => {
    if (value === undefined) {
      setPending(filterKey, []);
      return;
    }
    setPending(
      filterKey,
      (pendingFilters[filterKey] ?? []).filter((item) => item !== value),
    );
  };

  const dateValue = dateKey ? pendingFilters[dateKey]?.[0] : undefined;

  const grid = (items: FilterOption[], prepend?: ReactNode) => (
    <DataTableFilterCustom
      gridClassName={FILTER_GRID_CLASS}
      filters={items}
      prependElement={prepend}
      hideClearButton
      mode={DATA_TABLE_FILTER_MODE.BATCH}
      onBatchChange={setPending}
      getFilterValue={getFilterValue}
    />
  );

  return (
    <BatchFiltersLayout
      testIdPrefix={testIdPrefix}
      controlsClassName="gap-3"
      controls={
        <>
          {primary.length > 0 ? (
            <div className="min-w-0 flex-1">{grid(primary)}</div>
          ) : null}
          {hasMore ? (
            <Button
              variant="outline"
              size="lg"
              onClick={() => setIsExpanded(!isExpanded)}
              aria-expanded={isExpanded}
            >
              {isExpanded ? "Less Filters" : "More Filters"}
              <ChevronDown
                aria-hidden="true"
                className={`size-4 transition-transform duration-300 ${isExpanded ? "rotate-180" : "rotate-0"}`}
              />
            </Button>
          ) : null}
          {trailingControls}
        </>
      }
      expandedFilters={
        hasMore ? (
          <ExpandableSection isExpanded={isExpanded} contentClassName="pt-0">
            {grid(
              more,
              dateKey ? (
                <CustomDatePicker
                  onBatchChange={(_key, value) =>
                    setPending(dateKey, value ? [value] : [])
                  }
                  value={dateValue}
                />
              ) : undefined,
            )}
          </ExpandableSection>
        ) : null
      }
      expandedFiltersVisible={isExpanded}
      appliedSummary={
        <FilterSummaryStrip
          chips={appliedChips}
          onRemove={removeAppliedAndApply}
          trailingContent={
            <ClearFiltersButton
              showCount
              onClear={clearAndApply}
              pendingCount={appliedCount}
            />
          }
        />
      }
      pendingSummary={
        <FilterSummaryStrip
          chips={pendingChips}
          onRemove={removePendingChip}
          trailingContent={
            <ApplyFiltersButton
              hasChanges={hasChanges}
              changeCount={changeCount}
              onApply={applyAll}
              onDiscard={discardAll}
            />
          }
        />
      }
      showAppliedRow={appliedChips.length > 0}
      showPendingRow={hasChanges}
    />
  );
};

export type { StandardFilter };
