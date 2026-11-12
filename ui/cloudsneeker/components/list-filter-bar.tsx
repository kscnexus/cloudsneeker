import {
  LIST_PARAM,
  type ListFilters,
  listHref,
  type ListPagination,
} from "@/cloudsneeker/lib/list-filters";
import { DataTableSearch } from "@/components/shadcn/table/data-table-search";

import { PageNav } from "./page-nav";
import { StandardFilters } from "./standard/standard-filters";
import type { StandardFilter } from "./standard/standard-filters.utils";

export interface ListSelectOption {
  value: string;
  label: string;
}

export interface ListSelect {
  name:
    | typeof LIST_PARAM.PROVIDER
    | typeof LIST_PARAM.STATUS
    | typeof LIST_PARAM.TYPE;
  label: string;
  allLabel: string;
  options: ListSelectOption[];
}

interface ListFilterBarProps {
  path: string;
  /** Parameters every link keeps (for example the active tab). */
  keep: Record<string, string>;
  filters: ListFilters;
  searchPlaceholder: string;
  selects?: ListSelect[];
}

/** "All accounts" -> "Accounts": the dropdown placeholder reads "All <label>". */
const pluralLabel = (select: ListSelect): string => {
  const text = select.allLabel.replace(/^(All|Any)\s+/i, "").trim();
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : select.label;
};

export const listSelectFilters = (selects: ListSelect[]): StandardFilter[] =>
  selects.map((select) => ({
    key: select.name,
    label: pluralLabel(select),
    single: true,
    options: select.options,
  }));

/** The Cloud Security Findings filter bar for the smaller lists: one select
 * per field (applied together, with chips) and the search box. State lives in
 * the URL (`filter[...]`), so reloads, links and pages keep it. */
export const ListFilterBar = ({
  searchPlaceholder,
  selects = [],
}: ListFilterBarProps) => (
  <StandardFilters
    testIdPrefix="list"
    filters={listSelectFilters(selects)}
    trailingControls={
      <div className="w-full md:w-80">
        <DataTableSearch placeholder={`${searchPlaceholder} (press Enter)`} />
      </div>
    }
  />
);

interface ListPagerProps {
  path: string;
  keep: Record<string, string>;
  filters: ListFilters;
  pagination: ListPagination;
  noun: string;
}

/** "N items", "Page X of Y" and numbered pages (see `PageNav`). */
export const ListPager = ({
  path,
  keep,
  filters,
  pagination,
  noun,
}: ListPagerProps) => (
  <PageNav
    page={pagination.page}
    pages={pagination.pages}
    count={pagination.count}
    noun={noun}
    hrefFor={(page) => listHref(path, keep, { ...filters, page })}
  />
);
