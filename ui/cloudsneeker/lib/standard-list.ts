// URL conventions of the standard list pages, the same ones the Cloud
// Security Findings page uses: `filter[<field>]` with comma-separated values,
// `filter[search]`, `page`, `pageSize` and `sort`. Pages read these through
// the helpers below; legacy parameter names stay readable so old links,
// alerts and bookmarks keep working.

import type { SearchParamsProps } from "@/types";

export const STANDARD_PARAM = {
  PAGE: "page",
  PAGE_SIZE: "pageSize",
  SORT: "sort",
  SEARCH: "filter[search]",
} as const;

/** Rows-per-page choices of the Findings pagination. */
export const PAGE_SIZE_OPTIONS: readonly number[] = [10, 20, 30, 50, 100];

export const MAX_PAGE_SIZE = 100;

/** `filter[field]` for a field name; keys that already have it pass through. */
export const filterParam = (field: string): string =>
  field.startsWith("filter[") ? field : `filter[${field}]`;

const firstValue = (value: string | string[] | undefined): string => {
  if (Array.isArray(value)) return value[0] ?? "";
  return value ?? "";
};

const splitValues = (value: string): string[] =>
  value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

/** Values of `filter[field]`, or of the first legacy name that is set. */
export const readFilterList = (
  params: SearchParamsProps,
  field: string,
  legacy: readonly string[] = [],
): string[] => {
  for (const name of [filterParam(field), ...legacy]) {
    const values = splitValues(firstValue(params[name]));
    if (values.length > 0) return Array.from(new Set(values));
  }
  return [];
};

/** First value of `filter[field]` (or a legacy name), "" when unset. */
export const readFilterValue = (
  params: SearchParamsProps,
  field: string,
  legacy: readonly string[] = [],
): string => readFilterList(params, field, legacy)[0] ?? "";

/** The search box (`filter[search]`), or a legacy name. */
export const readSearch = (
  params: SearchParamsProps,
  legacy: readonly string[] = [],
): string => {
  for (const name of [STANDARD_PARAM.SEARCH, ...legacy]) {
    const value = firstValue(params[name]).trim();
    if (value) return value;
  }
  return "";
};

export const readPage = (params: SearchParamsProps): number => {
  const page = Number.parseInt(firstValue(params[STANDARD_PARAM.PAGE]), 10);
  return Number.isFinite(page) && page > 0 ? page : 1;
};

/** `pageSize` within 1..100, or the page's default. */
export const readPageSize = (
  params: SearchParamsProps,
  fallback: number,
): number => {
  const size = Number.parseInt(
    firstValue(params[STANDARD_PARAM.PAGE_SIZE]),
    10,
  );
  if (!Number.isFinite(size) || size < 1) return fallback;
  return Math.min(size, MAX_PAGE_SIZE);
};

/** Sets or removes list parameters on a query string. */
export const withListParams = (
  base: URLSearchParams,
  values: Record<string, string | readonly string[] | number | null | undefined>,
): URLSearchParams => {
  const next = new URLSearchParams(base.toString());
  Object.entries(values).forEach(([name, value]) => {
    const text = Array.isArray(value)
      ? value.filter(Boolean).join(",")
      : value === null || value === undefined
        ? ""
        : String(value);
    if (text) next.set(name, text);
    else next.delete(name);
  });
  return next;
};
