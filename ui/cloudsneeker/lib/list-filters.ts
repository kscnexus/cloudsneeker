// Server-side list filters shared by the Governance policy and run lists and
// the Application Security target list: search, one or two selects, a page.
// State lives in the URL so filters survive reloads, links and pagination.

export const LIST_PARAM = {
  SEARCH: "q",
  PROVIDER: "provider",
  STATUS: "status",
  TYPE: "type",
  PAGE: "page",
} as const;

export const LIST_PAGE_SIZE = 25;

/** Values of the policy list's schedule select. */
export const POLICY_SCHEDULE = {
  ON: "scheduled",
  OFF: "unscheduled",
} as const;

export interface ListFilters {
  search: string;
  provider: string;
  status: string;
  type: string;
  page: number;
}

type Params = Record<string, string | string[] | undefined>;

const first = (params: Params, key: string): string => {
  const value = params[key];
  return (Array.isArray(value) ? value[0] : value)?.trim() ?? "";
};

export const parseListFilters = (params: Params): ListFilters => {
  const page = Number.parseInt(first(params, LIST_PARAM.PAGE), 10);
  return {
    search: first(params, LIST_PARAM.SEARCH).slice(0, 200),
    provider: first(params, LIST_PARAM.PROVIDER),
    status: first(params, LIST_PARAM.STATUS),
    type: first(params, LIST_PARAM.TYPE),
    page: Number.isFinite(page) && page > 0 ? page : 1,
  };
};

export const hasListFilters = (filters: ListFilters): boolean =>
  Boolean(filters.search || filters.provider || filters.status || filters.type);

/** Link to the same list with some filters changed (others kept). */
export const listHref = (
  path: string,
  keep: Record<string, string>,
  filters: Partial<ListFilters>,
): string => {
  const params = new URLSearchParams(keep);
  if (filters.search) params.set(LIST_PARAM.SEARCH, filters.search);
  if (filters.provider) params.set(LIST_PARAM.PROVIDER, filters.provider);
  if (filters.status) params.set(LIST_PARAM.STATUS, filters.status);
  if (filters.type) params.set(LIST_PARAM.TYPE, filters.type);
  if (filters.page && filters.page > 1) {
    params.set(LIST_PARAM.PAGE, String(filters.page));
  }
  const query = params.toString();
  return query ? `${path}?${query}` : path;
};

/** Query for `custodian-policies`. */
export const policyListQuery = (
  filters: ListFilters,
): Record<string, string> => ({
  "page[size]": String(LIST_PAGE_SIZE),
  "page[number]": String(filters.page),
  sort: "name",
  ...(filters.search ? { "filter[search]": filters.search } : {}),
  ...(filters.provider ? { "filter[provider]": filters.provider } : {}),
  // The policy list uses the "type" select for its schedule (on / off).
  ...(filters.type === POLICY_SCHEDULE.ON ||
  filters.type === POLICY_SCHEDULE.OFF
    ? {
        "filter[schedule_enabled]": String(filters.type === POLICY_SCHEDULE.ON),
      }
    : {}),
});

/** Query for `custodian-runs`. */
export const runListQuery = (filters: ListFilters): Record<string, string> => ({
  "page[size]": String(LIST_PAGE_SIZE),
  "page[number]": String(filters.page),
  sort: "-inserted_at",
  ...(filters.search ? { "filter[search]": filters.search } : {}),
  ...(filters.provider ? { "filter[provider]": filters.provider } : {}),
  ...(filters.status ? { "filter[status]": filters.status } : {}),
});

export interface ListPagination {
  page: number;
  pages: number;
  count: number;
}

export const paginationOf = (
  response: unknown,
  page: number,
): ListPagination => {
  const meta = (
    response as
      | { meta?: { pagination?: { pages?: unknown; count?: unknown } } }
      | undefined
  )?.meta?.pagination;
  const pages =
    typeof meta?.pages === "number" && meta.pages > 0 ? meta.pages : 1;
  const count = typeof meta?.count === "number" ? meta.count : 0;
  return { page: Math.min(page, pages), pages, count };
};

/** Filter a loaded list in memory (lists the API returns whole). */
export const filterInMemory = <T>(
  items: T[],
  filters: ListFilters,
  fields: {
    text: (item: T) => string[];
    provider?: (item: T) => string;
    status?: (item: T) => string;
    type?: (item: T) => string;
  },
): T[] => {
  const needle = filters.search.toLowerCase();
  return items.filter((item) => {
    if (
      needle &&
      !fields.text(item).some((value) => value.toLowerCase().includes(needle))
    ) {
      return false;
    }
    if (filters.provider && fields.provider?.(item) !== filters.provider) {
      return false;
    }
    if (filters.status && fields.status?.(item) !== filters.status) {
      return false;
    }
    if (filters.type && fields.type?.(item) !== filters.type) return false;
    return true;
  });
};

/** One page of an in-memory list. */
export const pageOf = <T>(
  items: T[],
  page: number,
  size = LIST_PAGE_SIZE,
): { rows: T[]; pagination: ListPagination } => {
  const pages = Math.max(1, Math.ceil(items.length / size));
  const current = Math.min(Math.max(1, page), pages);
  return {
    rows: items.slice((current - 1) * size, current * size),
    pagination: { page: current, pages, count: items.length },
  };
};
