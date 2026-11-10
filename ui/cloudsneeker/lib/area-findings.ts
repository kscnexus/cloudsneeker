// Area findings and triage: per-area labels, page filters, API query and
// links. Cloud Security, Application Security and Cloud Governance share
// these helpers; each area keeps its own pages and data
// (`knowledge-base/area-findings.md`).

import { BRAND } from "@/cloudsneeker/brand";
import {
  TRIAGE_PAGE_PARAM,
  TRIAGE_PAGE_SIZE,
  TRIAGE_STATUS_FILTERS,
  TRIAGE_STATUS_PARAM,
  triageFindingsHref,
} from "@/cloudsneeker/lib/finding-triage";
import {
  AREA_PAGE_SEGMENT,
  appSecurityHref,
  findingTriageHref,
  governanceHref,
} from "@/cloudsneeker/routes";
import {
  AREA_FIX_FILTER,
  type AreaFixFilter,
  FINDING_AREA,
  type FindingArea,
  RISK_PRIORITIES,
  type RiskPriority,
  SECURITY_CATEGORIES,
  type SecurityCategory,
} from "@/cloudsneeker/types/area-findings";
import type { FindingTriageStatus } from "@/types/findings-triage";

export const AREA_FINDINGS_PAGE_SIZE = 25;

export const AREA_SEVERITIES = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
] as const;

export type AreaSeverity = (typeof AREA_SEVERITIES)[number];

export const AREA_FINDING_SORT = {
  SEVERITY: "severity",
  NEWEST: "-last_seen_at",
  OLDEST: "first_seen_at",
  CHECK: "check_id",
  EXPLOIT: "-epss",
} as const;

export type AreaFindingSort =
  (typeof AREA_FINDING_SORT)[keyof typeof AREA_FINDING_SORT];

export const AREA_FINDING_SORT_LABEL: Record<AreaFindingSort, string> = {
  [AREA_FINDING_SORT.SEVERITY]: "Severity",
  [AREA_FINDING_SORT.NEWEST]: "Last seen",
  [AREA_FINDING_SORT.OLDEST]: "First seen",
  [AREA_FINDING_SORT.CHECK]: "Rule",
  [AREA_FINDING_SORT.EXPLOIT]: "Exploit likelihood",
};

/** Query string names on the area pages. */
export const AREA_PARAM = {
  SEVERITY: "severity",
  TRIAGE: "triage",
  SOURCE: "source",
  SEARCH: "q",
  SORT: "sort",
  PAGE: "page",
  FIX: "fix",
  EXPLOITED: "exploited",
  CATEGORY: "category",
  PRIORITY: "priority",
  OVERDUE: "overdue",
  APPLICATION: "app",
} as const;

export const AREA_FIX_FILTER_LABEL: Record<AreaFixFilter, string> = {
  [AREA_FIX_FILTER.AVAILABLE]: "Fix available",
  [AREA_FIX_FILTER.UNAVAILABLE]: "No fix yet",
};

export interface AreaConfig {
  area: FindingArea;
  name: string;
  /** Findings page of the area (Cloud Security keeps the detailed `/findings`). */
  findingsHref: string;
  triageHref: string;
  checkLabel: string;
  resourceLabel: string;
  sourceLabel: string;
  emptyFindings: string;
  /** Findings carry fix data (governance dry runs do not). */
  showFix: boolean;
  /** Findings can be CVEs with EPSS and CISA KEV data. */
  showExploit: boolean;
  /** Findings carry a security category (SAST, SCA, secrets, IaC, container). */
  showCategory: boolean;
}

export const AREA_CONFIG: Record<FindingArea, AreaConfig> = {
  [FINDING_AREA.CLOUD]: {
    area: FINDING_AREA.CLOUD,
    name: BRAND.cloudSecurityName,
    findingsHref: "/findings",
    triageHref: findingTriageHref(),
    checkLabel: "Check",
    resourceLabel: "Resource",
    sourceLabel: "Provider",
    emptyFindings: "Run a scan on a cloud provider to see findings here.",
    showFix: true,
    showExploit: false,
    showCategory: false,
  },
  [FINDING_AREA.APPLICATION_SECURITY]: {
    area: FINDING_AREA.APPLICATION_SECURITY,
    name: BRAND.appSecurityName,
    findingsHref: appSecurityHref(AREA_PAGE_SEGMENT.FINDINGS),
    triageHref: appSecurityHref(AREA_PAGE_SEGMENT.TRIAGE),
    checkLabel: "Rule or CVE",
    resourceLabel: "Package or file",
    sourceLabel: "Target",
    emptyFindings:
      "Scan a repository, image or archive target to see its findings here.",
    showFix: true,
    showExploit: true,
    showCategory: true,
  },
  [FINDING_AREA.GOVERNANCE]: {
    area: FINDING_AREA.GOVERNANCE,
    name: BRAND.governanceName,
    findingsHref: governanceHref(AREA_PAGE_SEGMENT.FINDINGS),
    triageHref: governanceHref(AREA_PAGE_SEGMENT.TRIAGE),
    checkLabel: "Policy rule",
    resourceLabel: "Resource",
    sourceLabel: "Policy",
    emptyFindings: "Run a policy dry run to see the resources it matches here.",
    showFix: false,
    showExploit: false,
    showCategory: false,
  },
};

export interface AreaFindingFilters {
  severities: AreaSeverity[];
  triage: FindingTriageStatus | null;
  source: string | null;
  search: string;
  sort: AreaFindingSort;
  page: number;
  fix: AreaFixFilter | null;
  /** Only CVEs in the CISA Known Exploited Vulnerabilities catalog. */
  exploited?: boolean;
  /** Application Security security category. */
  category?: SecurityCategory;
  /** Application Security risk priority. */
  priority?: RiskPriority;
  /** Application Security: past the remediation due date. */
  overdue?: boolean;
  /** Application Security: linked provider (repository) id. */
  application?: string;
}

/** Sort options an area offers (exploit likelihood needs CVE findings). */
export const areaSortOptions = (area: FindingArea): AreaFindingSort[] =>
  Object.values(AREA_FINDING_SORT).filter(
    (sort) =>
      sort !== AREA_FINDING_SORT.EXPLOIT || AREA_CONFIG[area].showExploit,
  );

type ParamValue = string | string[] | undefined;

const first = (value: ParamValue): string =>
  (Array.isArray(value) ? value[0] : value)?.trim() ?? "";

const parsePage = (value: ParamValue): number => {
  const candidate = Number(first(value));
  return Number.isInteger(candidate) && candidate > 0 ? candidate : 1;
};

/** Page filters from the URL; unknown values fall back to the defaults. */
export const parseAreaFilters = (
  params: Record<string, ParamValue>,
): AreaFindingFilters => {
  const severities = first(params[AREA_PARAM.SEVERITY])
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter((value): value is AreaSeverity =>
      (AREA_SEVERITIES as readonly string[]).includes(value),
    );
  const triage = first(params[AREA_PARAM.TRIAGE]);
  const sort = first(params[AREA_PARAM.SORT]);
  const fix = first(params[AREA_PARAM.FIX]);
  const category = SECURITY_CATEGORIES.find(
    (value) => value === first(params[AREA_PARAM.CATEGORY]).toLowerCase(),
  );
  const priority = RISK_PRIORITIES.find(
    (value) => value === first(params[AREA_PARAM.PRIORITY]).toLowerCase(),
  );
  const application = first(params[AREA_PARAM.APPLICATION]).slice(0, 64);
  return {
    severities: Array.from(new Set(severities)),
    triage: TRIAGE_STATUS_FILTERS.find((status) => status === triage) ?? null,
    source: first(params[AREA_PARAM.SOURCE]) || null,
    search: first(params[AREA_PARAM.SEARCH]).slice(0, 200),
    sort: (Object.values(AREA_FINDING_SORT) as string[]).includes(sort)
      ? (sort as AreaFindingSort)
      : AREA_FINDING_SORT.SEVERITY,
    page: parsePage(params[AREA_PARAM.PAGE]),
    fix: Object.values(AREA_FIX_FILTER).find((value) => value === fix) ?? null,
    ...(first(params[AREA_PARAM.EXPLOITED]) === "1" ? { exploited: true } : {}),
    ...(category ? { category } : {}),
    ...(priority ? { priority } : {}),
    ...(first(params[AREA_PARAM.OVERDUE]) === "1" ? { overdue: true } : {}),
    ...(application ? { application } : {}),
  };
};

/** Query for `GET /area-findings`. */
export const areaFindingsSearchParams = (
  area: FindingArea,
  filters: AreaFindingFilters,
): Record<string, string> => ({
  "filter[area]": area,
  "page[number]": String(filters.page),
  "page[size]": String(AREA_FINDINGS_PAGE_SIZE),
  sort: filters.sort,
  ...(filters.severities.length
    ? { "filter[severity__in]": filters.severities.join(",") }
    : {}),
  ...(filters.triage ? { "filter[triage_status__in]": filters.triage } : {}),
  ...(filters.source ? { "filter[source__in]": filters.source } : {}),
  ...(filters.search ? { "filter[search]": filters.search } : {}),
  ...(filters.fix && AREA_CONFIG[area].showFix
    ? { "filter[fix]": filters.fix }
    : {}),
  ...(filters.exploited && AREA_CONFIG[area].showExploit
    ? { "filter[known_exploited]": "true" }
    : {}),
  ...(filters.category && AREA_CONFIG[area].showCategory
    ? { "filter[category__in]": filters.category }
    : {}),
  ...(AREA_CONFIG[area].showCategory
    ? {
        ...(filters.priority
          ? { "filter[priority__in]": filters.priority }
          : {}),
        ...(filters.overdue ? { "filter[overdue]": "true" } : {}),
        ...(filters.application
          ? { "filter[application__in]": filters.application }
          : {}),
      }
    : {}),
});

/** Query for `GET /finding-triages` of one area. */
export const areaTriageSearchParams = (
  area: FindingArea,
  status: FindingTriageStatus | null,
  page: number,
): Record<string, string> => ({
  "filter[area]": area,
  "page[number]": String(page),
  "page[size]": String(TRIAGE_PAGE_SIZE),
  sort: "-updated_at",
  ...(status ? { "filter[status]": status } : {}),
});

const withQuery = (base: string, params: URLSearchParams): string => {
  const query = params.toString();
  return query ? `${base}?${query}` : base;
};

/** Area findings link with the given filters (defaults are left out). */
export const areaFindingsPageHref = (
  area: FindingArea,
  filters: Partial<AreaFindingFilters>,
): string => {
  const params = new URLSearchParams();
  if (filters.severities?.length) {
    params.set(AREA_PARAM.SEVERITY, filters.severities.join(","));
  }
  if (filters.triage) params.set(AREA_PARAM.TRIAGE, filters.triage);
  if (filters.source) params.set(AREA_PARAM.SOURCE, filters.source);
  if (filters.search) params.set(AREA_PARAM.SEARCH, filters.search);
  if (filters.sort && filters.sort !== AREA_FINDING_SORT.SEVERITY) {
    params.set(AREA_PARAM.SORT, filters.sort);
  }
  if (filters.fix) params.set(AREA_PARAM.FIX, filters.fix);
  if (filters.exploited) params.set(AREA_PARAM.EXPLOITED, "1");
  if (filters.category) params.set(AREA_PARAM.CATEGORY, filters.category);
  if (filters.priority) params.set(AREA_PARAM.PRIORITY, filters.priority);
  if (filters.overdue) params.set(AREA_PARAM.OVERDUE, "1");
  if (filters.application) {
    params.set(AREA_PARAM.APPLICATION, filters.application);
  }
  if (filters.page && filters.page > 1) {
    params.set(AREA_PARAM.PAGE, String(filters.page));
  }
  return withQuery(AREA_CONFIG[area].findingsHref, params);
};

/** Area triage link for a status tab (null = all statuses). */
export const areaTriagePageHref = (
  area: FindingArea,
  status: FindingTriageStatus | null,
  page = 1,
): string => {
  const params = new URLSearchParams();
  if (status) params.set(TRIAGE_STATUS_PARAM, status);
  if (page > 1) params.set(TRIAGE_PAGE_PARAM, String(page));
  return withQuery(AREA_CONFIG[area].triageHref, params);
};

/** Detail page of one Application Security finding. */
export const appSecurityFindingHref = (uid: string): string =>
  appSecurityHref(AREA_PAGE_SEGMENT.FINDINGS, uid);

/** Where a triaged finding is opened: the cloud check, the Application
 * Security detail page, else the area search. */
export const areaFindingHref = (
  area: FindingArea,
  finding: { uid: string; checkId: string },
): string => {
  if (area === FINDING_AREA.CLOUD) return triageFindingsHref(finding.checkId);
  if (area === FINDING_AREA.APPLICATION_SECURITY) {
    return appSecurityFindingHref(finding.uid);
  }
  return areaFindingsPageHref(area, { search: finding.uid });
};

/** Toggle one severity in the active set (for the severity chips). */
export const toggleSeverity = (
  active: readonly AreaSeverity[],
  severity: AreaSeverity,
): AreaSeverity[] =>
  active.includes(severity)
    ? active.filter((value) => value !== severity)
    : AREA_SEVERITIES.filter(
        (value) => value === severity || active.includes(value),
      );
