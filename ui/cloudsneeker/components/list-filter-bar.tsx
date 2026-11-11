import Link from "next/link";

import {
  hasListFilters,
  LIST_PARAM,
  type ListFilters,
  listHref,
  type ListPagination,
} from "@/cloudsneeker/lib/list-filters";
import { FORM_SELECT_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { Button, Input } from "@/components/shadcn";
import { cn } from "@/lib/utils";

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

/** Search and selects submitted as a GET form: works without client code,
 * keeps state in the URL and resets to page 1 on every change. */
export const ListFilterBar = ({
  path,
  keep,
  filters,
  searchPlaceholder,
  selects = [],
}: ListFilterBarProps) => (
  <form
    method="get"
    action={path}
    className="flex flex-wrap items-end gap-3"
    role="search"
  >
    {Object.entries(keep).map(([name, value]) => (
      <input key={name} type="hidden" name={name} value={value} />
    ))}
    <label className="flex min-w-[220px] flex-1 flex-col gap-1 text-xs font-medium">
      <span className="text-text-neutral-secondary">Search</span>
      <Input
        name={LIST_PARAM.SEARCH}
        defaultValue={filters.search}
        placeholder={searchPlaceholder}
        aria-label="Search"
      />
    </label>
    {selects.map((select) => (
      <label
        key={select.name}
        className="flex min-w-[180px] flex-col gap-1 text-xs font-medium"
      >
        <span className="text-text-neutral-secondary">{select.label}</span>
        <select
          name={select.name}
          defaultValue={filters[select.name]}
          className={cn(FORM_SELECT_CLASS, "h-9")}
          aria-label={select.label}
        >
          <option value="">{select.allLabel}</option>
          {select.options.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
    ))}
    <Button type="submit" size="sm">
      Apply
    </Button>
    {hasListFilters(filters) ? (
      <Button asChild size="sm" variant="ghost">
        <Link href={listHref(path, keep, {})}>Clear all</Link>
      </Button>
    ) : null}
  </form>
);

interface ListPagerProps {
  path: string;
  keep: Record<string, string>;
  filters: ListFilters;
  pagination: ListPagination;
  noun: string;
}

/** "N items · Page X of Y" with previous and next links. */
export const ListPager = ({
  path,
  keep,
  filters,
  pagination,
  noun,
}: ListPagerProps) => (
  <nav
    aria-label={`${noun} pages`}
    className="text-text-neutral-secondary flex flex-wrap items-center justify-between gap-2 text-sm"
  >
    <span>
      {pagination.count} {noun}
      {pagination.pages > 1
        ? ` · Page ${pagination.page} of ${pagination.pages}`
        : ""}
    </span>
    {pagination.pages > 1 ? (
      <span className="flex gap-2">
        {pagination.page > 1 ? (
          <Button asChild size="xs" variant="outline">
            <Link
              href={listHref(path, keep, {
                ...filters,
                page: pagination.page - 1,
              })}
            >
              Previous
            </Link>
          </Button>
        ) : null}
        {pagination.page < pagination.pages ? (
          <Button asChild size="xs" variant="outline">
            <Link
              href={listHref(path, keep, {
                ...filters,
                page: pagination.page + 1,
              })}
            >
              Next
            </Link>
          </Button>
        ) : null}
      </span>
    ) : null}
  </nav>
);
