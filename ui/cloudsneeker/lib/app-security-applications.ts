// Application Inventory: an application is a linked source (repository,
// registry or cluster) with one or more targets. Targets are grouped by
// provider id; finding counts come from `summary=applications`.

import {
  APPLICATION_POSTURE_LABEL,
  applicationPosture,
} from "@/cloudsneeker/lib/app-security-priority";
import {
  parsePage,
  scanTypeLabel,
} from "@/cloudsneeker/lib/app-security-scans";
import { APP_SECURITY_SEGMENT, appSecurityHref } from "@/cloudsneeker/routes";
import type { AreaApplicationSummary } from "@/cloudsneeker/types/area-findings";
import type { TrivyTargetResource } from "@/cloudsneeker/types/trivy";

/** Applications per inventory page. */
export const APPLICATIONS_PAGE_SIZE = 25;

export interface Application {
  /** Provider id. */
  id: string;
  name: string;
  /** Provider uid: the repository URL, registry or cluster. */
  repository: string;
  /** Distinct target modes, in first-seen order. */
  modes: string[];
  targets: TrivyTargetResource[];
  summary?: AreaApplicationSummary;
}

/** Targets grouped by provider; targets without a provider are skipped. */
export const groupTargetsIntoApplications = (
  targets: readonly TrivyTargetResource[],
): Application[] => {
  const applications = new Map<string, Application>();
  for (const target of targets) {
    const {
      provider_id: id,
      provider_alias,
      provider_uid,
      mode,
    } = target.attributes;
    if (!id) continue;
    const existing = applications.get(id);
    if (existing) {
      existing.targets.push(target);
      if (mode && !existing.modes.includes(mode)) existing.modes.push(mode);
      continue;
    }
    applications.set(id, {
      id,
      name: provider_alias || provider_uid || id,
      repository: provider_uid || "",
      modes: mode ? [mode] : [],
      targets: [target],
    });
  }
  return Array.from(applications.values());
};

/** `meta.applications` of an area findings response. */
export const responseApplicationSummaries = (
  response: unknown,
): AreaApplicationSummary[] => {
  const items = (response as { meta?: { applications?: unknown } } | null)?.meta
    ?.applications;
  return Array.isArray(items)
    ? items.filter(
        (item): item is AreaApplicationSummary =>
          !!item &&
          typeof item === "object" &&
          typeof (item as { id?: unknown }).id === "string",
      )
    : [];
};

export const attachSummaries = (
  applications: readonly Application[],
  summaries: readonly AreaApplicationSummary[],
): Application[] => {
  const byId = new Map(summaries.map((summary) => [summary.id, summary]));
  return applications.map((application) => ({
    ...application,
    summary: byId.get(application.id) ?? application.summary,
  }));
};

export const scanTypeLabels = (application: Application): string[] =>
  application.modes.map(scanTypeLabel);

export const applicationPostureLabel = (application: Application): string =>
  APPLICATION_POSTURE_LABEL[applicationPosture(application.summary)];

/** Case-insensitive match on name or repository. */
export const searchApplications = (
  applications: readonly Application[],
  query: string | undefined,
): Application[] => {
  const needle = query?.trim().toLowerCase();
  if (!needle) return [...applications];
  return applications.filter(
    (application) =>
      application.name.toLowerCase().includes(needle) ||
      application.repository.toLowerCase().includes(needle),
  );
};

export const APPLICATION_SORT = {
  RISK: "risk",
  NAME: "name",
  FINDINGS: "findings",
} as const;

export type ApplicationSort =
  (typeof APPLICATION_SORT)[keyof typeof APPLICATION_SORT];

export const APPLICATION_SORT_LABEL: Record<ApplicationSort, string> = {
  [APPLICATION_SORT.RISK]: "Highest risk",
  [APPLICATION_SORT.NAME]: "Name",
  [APPLICATION_SORT.FINDINGS]: "Most findings",
};

export const APPLICATION_SORTS: readonly ApplicationSort[] =
  Object.values(APPLICATION_SORT);

type QueryValue = string | string[] | undefined;

const first = (value: QueryValue): string | undefined =>
  (Array.isArray(value) ? value[0] : value)?.trim() || undefined;

export const getApplicationSort = (value: QueryValue): ApplicationSort => {
  const sort = first(value);
  return sort && (APPLICATION_SORTS as readonly string[]).includes(sort)
    ? (sort as ApplicationSort)
    : APPLICATION_SORT.RISK;
};

const byName = (a: Application, b: Application): number =>
  a.name.localeCompare(b.name, undefined, { sensitivity: "base" });

const count = (
  application: Application,
  key: keyof Omit<AreaApplicationSummary, "id">,
): number => application.summary?.[key] ?? 0;

/** Risk: urgent, critical, high, total (all descending), then name. */
export const sortApplications = (
  applications: readonly Application[],
  sort: ApplicationSort,
): Application[] => {
  const sorted = [...applications];
  if (sort === APPLICATION_SORT.NAME) return sorted.sort(byName);
  if (sort === APPLICATION_SORT.FINDINGS) {
    return sorted.sort(
      (a, b) => count(b, "total") - count(a, "total") || byName(a, b),
    );
  }
  return sorted.sort(
    (a, b) =>
      count(b, "urgent") - count(a, "urgent") ||
      count(b, "critical") - count(a, "critical") ||
      count(b, "high") - count(a, "high") ||
      count(b, "total") - count(a, "total") ||
      byName(a, b),
  );
};

export interface PageSlice<T> {
  items: T[];
  page: number;
  pages: number;
  total: number;
}

/** One page of `items`; out-of-range pages clamp to the last page. */
export const paginate = <T>(
  items: readonly T[],
  page: number,
  pageSize: number = APPLICATIONS_PAGE_SIZE,
): PageSlice<T> => {
  const pages = Math.max(1, Math.ceil(items.length / pageSize));
  const current = Math.min(Math.max(1, Math.floor(page) || 1), pages);
  const start = (current - 1) * pageSize;
  return {
    items: items.slice(start, start + pageSize),
    page: current,
    pages,
    total: items.length,
  };
};

export const APPLICATIONS_PARAM = {
  QUERY: "q",
  SORT: "sort",
  PAGE: "page",
} as const;

export interface ApplicationsQuery {
  q?: string;
  sort: ApplicationSort;
  page: number;
}

export const parseApplicationsQuery = (
  searchParams: Record<string, QueryValue>,
): ApplicationsQuery => ({
  q: first(searchParams[APPLICATIONS_PARAM.QUERY]),
  sort: getApplicationSort(searchParams[APPLICATIONS_PARAM.SORT]),
  page: parsePage(searchParams[APPLICATIONS_PARAM.PAGE]),
});

/** Inventory URL; defaults (risk sort, page 1, no search) are left out. */
export const applicationsHref = (
  query: Partial<ApplicationsQuery> = {},
): string => {
  const params = new URLSearchParams();
  if (query.q) params.set(APPLICATIONS_PARAM.QUERY, query.q);
  if (query.sort && query.sort !== APPLICATION_SORT.RISK) {
    params.set(APPLICATIONS_PARAM.SORT, query.sort);
  }
  if (query.page && query.page > 1) {
    params.set(APPLICATIONS_PARAM.PAGE, String(query.page));
  }
  const serialized = params.toString();
  const base = appSecurityHref(APP_SECURITY_SEGMENT.APPLICATIONS);
  return serialized ? `${base}?${serialized}` : base;
};

export const APPLICATION_TAB = {
  OVERVIEW: "overview",
  TARGETS: "targets",
  FINDINGS: "findings",
  SCANS: "scans",
} as const;

export type ApplicationTab =
  (typeof APPLICATION_TAB)[keyof typeof APPLICATION_TAB];

export const APPLICATION_TAB_PARAM = "tab";

export const getApplicationTab = (value: QueryValue): ApplicationTab => {
  const tab = first(value);
  return tab &&
    (Object.values(APPLICATION_TAB) as readonly string[]).includes(tab)
    ? (tab as ApplicationTab)
    : APPLICATION_TAB.OVERVIEW;
};

/** Application detail URL; the overview tab has no query. */
export const applicationHref = (
  applicationId: string,
  tab: ApplicationTab = APPLICATION_TAB.OVERVIEW,
): string => {
  const base = appSecurityHref(
    APP_SECURITY_SEGMENT.APPLICATIONS,
    applicationId,
  );
  return tab === APPLICATION_TAB.OVERVIEW
    ? base
    : `${base}?${APPLICATION_TAB_PARAM}=${tab}`;
};
