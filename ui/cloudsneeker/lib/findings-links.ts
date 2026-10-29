// Findings drill-down links and small readers for JSON:API list responses,
// shared by the Overview risk view and the Application Security dashboard.

import { applyFailNonMutedFilters } from "@/lib/findings-filters";

export const FINDINGS_PATH = "/findings";

/** `/findings` filtered to open (failed, not muted) results plus `filters`. */
export const openFindingsHref = (
  filters: Record<string, string> = {},
): string => {
  const params = new URLSearchParams();
  applyFailNonMutedFilters(params);
  for (const [key, value] of Object.entries(filters)) {
    if (value) params.set(key, value);
  }
  return `${FINDINGS_PATH}?${params.toString()}`;
};

/** `data` of a list response, or an empty list for errors and blanks. */
export const responseList = <T>(response: unknown): T[] => {
  if (!response || typeof response !== "object") return [];
  const data = (response as { data?: unknown }).data;
  return Array.isArray(data) ? (data as T[]) : [];
};

/** `meta.pagination.count` of a list response, when the API sent one. */
export const responseCount = (response: unknown): number | null => {
  if (!response || typeof response !== "object") return null;
  const meta = (response as { meta?: unknown }).meta;
  if (!meta || typeof meta !== "object") return null;
  const pagination = (meta as { pagination?: unknown }).pagination;
  if (!pagination || typeof pagination !== "object") return null;
  const count = (pagination as { count?: unknown }).count;
  return typeof count === "number" && Number.isFinite(count) ? count : null;
};
