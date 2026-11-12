import type { FilterChip } from "@/components/filters/filter-summary-strip";
import {
  FILTER_SELECTION_MODE,
  type FilterOption,
  type FilterSelectionMode,
} from "@/types/filters";

export interface StandardFilterOption {
  value: string;
  label: string;
}

/** One dropdown of a standard filter bar. Plain data, so server pages can
 * build it; labels replace the functions the upstream options take. */
export interface StandardFilter {
  /** Field name; the URL parameter is `filter[<key>]`. */
  key: string;
  /** Plural label: the placeholder reads "All <label>". */
  label: string;
  options: StandardFilterOption[];
  /** One value at a time (a select) instead of a searchable multi-select. */
  single?: boolean;
  /** Wider dropdown for long labels. */
  wide?: boolean;
}

const normalize = (key: string): string =>
  key.startsWith("filter[") ? key : `filter[${key}]`;

export const toFilterOption = (filter: StandardFilter): FilterOption => {
  const labels = new Map(
    filter.options.map((option) => [option.value, option.label]),
  );
  const selectionMode: FilterSelectionMode = filter.single
    ? FILTER_SELECTION_MODE.SINGLE
    : FILTER_SELECTION_MODE.MULTIPLE;
  return {
    key: filter.key,
    labelCheckboxGroup: filter.label,
    values: filter.options.map((option) => option.value),
    labelFormatter: (value: string) => labels.get(value) ?? value,
    selectionMode,
    width: filter.wide ? "wide" : "default",
  };
};

/** One removable chip per selected value, labelled like the dropdown. */
export const buildStandardChips = (
  selected: Record<string, string[]>,
  filters: StandardFilter[],
): FilterChip[] => {
  const byKey = new Map(
    filters.map((filter) => [normalize(filter.key), filter]),
  );
  return Object.entries(selected).flatMap(([key, values]) => {
    const filter = byKey.get(normalize(key));
    if (!filter) return [];
    const labels = new Map(
      filter.options.map((option) => [option.value, option.label]),
    );
    return (values ?? []).filter(Boolean).map((value) => ({
      key: normalize(key),
      label: filter.label,
      value,
      displayValue: labels.get(value) ?? value,
    }));
  });
};
