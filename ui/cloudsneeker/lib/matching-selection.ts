// "Select all matching": the UIDs of every finding that matches the current
// filters, not only the visible page. Bulk triage and mute accept at most
// 500 findings, so the selection stops there and says so.

export const MATCHING_SELECTION_LIMIT = 500;
export const MATCHING_PAGE_SIZE = 100;

export const MATCHING_PAGES = Math.ceil(
  MATCHING_SELECTION_LIMIT / MATCHING_PAGE_SIZE,
);

/** The list query for one page of matching UIDs. */
export const matchingPageQuery = (
  query: Record<string, string | undefined>,
  page: number,
): Record<string, string | undefined> => ({
  ...query,
  "page[number]": String(page),
  "page[size]": String(MATCHING_PAGE_SIZE),
});

/** How many findings "Select all" will pick for a total. */
export const matchingSelectionSize = (total: number): number =>
  Math.min(Math.max(total, 0), MATCHING_SELECTION_LIMIT);

/** Label of the bulk bar's count. */
export const selectionLabel = (count: number, pageSize: number): string =>
  count > pageSize
    ? `${count} selected across pages`
    : `${count} selected on this page`;
