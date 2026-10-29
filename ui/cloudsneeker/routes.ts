// Product routes for Cloudsneeker-only areas. Pages, links and revalidation
// read these builders so a route change happens in one place. Engine names
// stay out of the URLs users see.

export const PRODUCT_ROUTE = {
  APPLICATION_SECURITY: "/application-security",
  GOVERNANCE: "/governance",
} as const;

export type ProductRoute = (typeof PRODUCT_ROUTE)[keyof typeof PRODUCT_ROUTE];

// Earlier releases served these areas under engine-named paths. They redirect
// to the product route with the same sub-path and query.
export const LEGACY_PRODUCT_ROUTE = {
  "/trivy": PRODUCT_ROUTE.APPLICATION_SECURITY,
  "/custodian": PRODUCT_ROUTE.GOVERNANCE,
} as const;

export type LegacyProductRoute = keyof typeof LEGACY_PRODUCT_ROUTE;

const joinRoute = (base: ProductRoute, segments: readonly string[]): string => {
  const path = segments
    .filter((segment) => segment.length > 0)
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  return path ? `${base}/${path}` : base;
};

export const appSecurityHref = (...segments: string[]): string =>
  joinRoute(PRODUCT_ROUTE.APPLICATION_SECURITY, segments);

export const governanceHref = (...segments: string[]): string =>
  joinRoute(PRODUCT_ROUTE.GOVERNANCE, segments);

type SearchParamValue = string | string[] | undefined;

const toQueryString = (
  searchParams: Record<string, SearchParamValue> = {},
): string => {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(searchParams)) {
    if (value === undefined) continue;
    for (const item of Array.isArray(value) ? value : [value]) {
      query.append(key, item);
    }
  }
  const serialized = query.toString();
  return serialized ? `?${serialized}` : "";
};

/** Product URL for a request to a legacy engine-named path. */
export const legacyRedirectHref = (
  legacy: LegacyProductRoute,
  segments: readonly string[] = [],
  searchParams: Record<string, SearchParamValue> = {},
): string =>
  joinRoute(LEGACY_PRODUCT_ROUTE[legacy], segments) +
  toQueryString(searchParams);
