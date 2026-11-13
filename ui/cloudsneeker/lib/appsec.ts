// Application Security (ASPM) helpers: page routes, list filters, labels.
// Pure functions; pages and components read these so URLs, API parameters
// and wording stay in one place.

import { TRIAGE_STATUS_FILTERS } from "@/cloudsneeker/lib/finding-triage";
import { appSecurityHref } from "@/cloudsneeker/routes";
import {
  APPSEC_CATEGORY,
  APPSEC_FEATURE_STATUS,
  APPSEC_POLICY_KIND,
  APPSEC_PRIORITY,
  APPSEC_SEVERITY,
  APPSEC_STATE,
  type AppSecCategory,
  type AppSecFeatureStatus,
  type AppSecFindingAttributes,
  type AppSecPolicyKind,
  type AppSecPriority,
  type AppSecSeverity,
  type AppSecState,
} from "@/cloudsneeker/types/appsec";
import { TRIVY_MODE } from "@/cloudsneeker/types/trivy";

type SearchParamValue = string | string[] | undefined;
type SearchParams = Record<string, SearchParamValue>;

/** Path segments under `/application-security`. */
export const APPSEC_SEGMENT = {
  APPLICATIONS: "applications",
  SCANS: "scans",
  VULNERABILITIES: "vulnerabilities",
  MISCONFIGURATIONS: "misconfigurations",
  SECRETS: "secrets",
  LICENSES: "licenses",
  CODE: "code",
  FINDINGS: "findings",
  COMPONENTS: "components",
  SBOMS: "sboms",
  PROFILES: "profiles",
  SETTINGS: "settings",
} as const;
export type AppSecSegment =
  (typeof APPSEC_SEGMENT)[keyof typeof APPSEC_SEGMENT];

/** Static segments, so a target id can never be mistaken for one. */
export const APPSEC_RESERVED_SEGMENTS: readonly string[] = [
  ...Object.values(APPSEC_SEGMENT),
  "new",
  "triage",
];

export const APPSEC_SEVERITIES: readonly AppSecSeverity[] = [
  APPSEC_SEVERITY.CRITICAL,
  APPSEC_SEVERITY.HIGH,
  APPSEC_SEVERITY.MEDIUM,
  APPSEC_SEVERITY.LOW,
  APPSEC_SEVERITY.INFORMATIONAL,
  APPSEC_SEVERITY.UNKNOWN,
];

export const APPSEC_STATES: readonly AppSecState[] = [
  APPSEC_STATE.NEW,
  APPSEC_STATE.OPEN,
  APPSEC_STATE.REOPENED,
  APPSEC_STATE.FIXED,
];

/** Business criticality of an application. */
export const APPSEC_CRITICALITIES = [
  "low",
  "medium",
  "high",
  "critical",
] as const;

/** Environment of an application. */
export const APPSEC_ENVIRONMENTS = [
  "production",
  "staging",
  "development",
  "test",
  "unknown",
] as const;

export const APPSEC_PRIORITIES: readonly AppSecPriority[] = [
  APPSEC_PRIORITY.URGENT,
  APPSEC_PRIORITY.HIGH,
  APPSEC_PRIORITY.MEDIUM,
  APPSEC_PRIORITY.LOW,
];

const SEVERITY_LABEL: Record<AppSecSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Informational",
  unknown: "Unknown",
};

const STATE_LABEL: Record<AppSecState, string> = {
  new: "New",
  open: "Open",
  reopened: "Reopened",
  fixed: "Fixed",
};

const PRIORITY_LABEL: Record<AppSecPriority, string> = {
  urgent: "Urgent",
  high: "High",
  medium: "Medium",
  low: "Low",
};

const CATEGORY_LABEL: Record<AppSecCategory, string> = {
  vulnerability: "Vulnerability",
  misconfiguration: "Misconfiguration",
  secret: "Secret",
  license: "License",
  code: "Code weakness",
};

const titleCase = (value: string): string =>
  value
    ? value.charAt(0).toUpperCase() + value.slice(1).replace(/_/g, " ")
    : "";

export const appSecSeverityLabel = (severity: string): string =>
  SEVERITY_LABEL[severity as AppSecSeverity] ?? titleCase(severity);
export const appSecStateLabel = (state: string): string =>
  STATE_LABEL[state as AppSecState] ?? titleCase(state);
export const appSecPriorityLabel = (priority: string): string =>
  PRIORITY_LABEL[priority as AppSecPriority] ?? titleCase(priority);
export const appSecCategoryLabel = (category: string): string =>
  CATEGORY_LABEL[category as AppSecCategory] ?? titleCase(category);

export interface AppSecWorkspace {
  segment: AppSecSegment;
  /** `null` lists every category. */
  category: AppSecCategory | null;
  title: string;
  description: string;
  /** Column heading for `rule_id`. */
  ruleLabel: string;
  empty: string;
}

/** Finding workspaces: one page per finding category, plus all findings. */
export const APPSEC_WORKSPACES: readonly AppSecWorkspace[] = [
  {
    segment: APPSEC_SEGMENT.VULNERABILITIES,
    category: APPSEC_CATEGORY.VULNERABILITY,
    title: "Vulnerabilities",
    description:
      "Known vulnerabilities in operating system and language packages. One row per vulnerability, package and location; rescans update the row instead of adding one.",
    ruleLabel: "Advisory",
    empty:
      "No vulnerabilities yet. Scan a repository, image, archive or SBOM with the vulnerability scanner.",
  },
  {
    segment: APPSEC_SEGMENT.MISCONFIGURATIONS,
    category: APPSEC_CATEGORY.MISCONFIGURATION,
    title: "Misconfigurations",
    description:
      "Failed configuration checks in Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, Azure ARM and Ansible files, and in cluster resources.",
    ruleLabel: "Check",
    empty:
      "No misconfigurations yet. Scan a repository or cluster with the misconfiguration scanner.",
  },
  {
    segment: APPSEC_SEGMENT.SECRETS,
    category: APPSEC_CATEGORY.SECRET,
    title: "Secrets",
    description:
      "Credentials, tokens and keys found in files and image layers. The matched value is masked everywhere; treat every secret listed here as leaked.",
    ruleLabel: "Rule",
    empty: "No secrets found. Scan a repository, archive or image for secrets.",
  },
  {
    segment: APPSEC_SEGMENT.LICENSES,
    category: APPSEC_CATEGORY.LICENSE,
    title: "License compliance",
    description:
      "Licenses of packages and files, classified by how restrictive they are. License severity is a legal risk level, not a vulnerability severity.",
    ruleLabel: "License",
    empty:
      "No license findings yet. Use a scan profile that includes the license scanner.",
  },
  {
    segment: APPSEC_SEGMENT.CODE,
    category: APPSEC_CATEGORY.CODE,
    title: "Code weaknesses",
    description:
      "Security bugs found by static analysis of source code, such as injection, unsafe deserialization and weak cryptography.",
    ruleLabel: "Rule",
    empty: "No code findings yet. Create a static analysis target and scan it.",
  },
  {
    segment: APPSEC_SEGMENT.FINDINGS,
    category: null,
    title: "All findings",
    description:
      "Every application security finding, ordered by priority. Priority combines scanner severity with exploitability, fix availability and the criticality of the application.",
    ruleLabel: "Rule",
    empty: "No findings yet. Create a target and run a scan.",
  },
];

export const workspaceForSegment = (
  segment: string,
): AppSecWorkspace | undefined =>
  APPSEC_WORKSPACES.find((workspace) => workspace.segment === segment);

export const workspaceForCategory = (category: string): AppSecWorkspace =>
  APPSEC_WORKSPACES.find((workspace) => workspace.category === category) ??
  APPSEC_WORKSPACES[APPSEC_WORKSPACES.length - 1];

export const appSecFindingHref = (findingId: string): string =>
  appSecurityHref(APPSEC_SEGMENT.FINDINGS, findingId);

export const appSecApplicationHref = (applicationId: string): string =>
  appSecurityHref(APPSEC_SEGMENT.APPLICATIONS, applicationId);

export const appSecSbomHref = (sbomId: string): string =>
  appSecurityHref(APPSEC_SEGMENT.SBOMS, sbomId);

/** Same-origin download proxy (`app/api/cloudsneeker/appsec/download`). */
export const APPSEC_DOWNLOAD_API = "/api/cloudsneeker/appsec/download";

export const APPSEC_DOWNLOAD_KIND = {
  SBOM: "sbom",
  SCAN: "scan",
  FINDINGS: "findings",
} as const;
export type AppSecDownloadKind =
  (typeof APPSEC_DOWNLOAD_KIND)[keyof typeof APPSEC_DOWNLOAD_KIND];

export const appSecDownloadHref = (
  kind: AppSecDownloadKind,
  format: string,
  params: Record<string, string> = {},
): string => {
  const query = new URLSearchParams({ kind, format, ...params });
  return `${APPSEC_DOWNLOAD_API}?${query.toString()}`;
};

// --- Findings list filters ---------------------------------------------------

/** Query string names of the findings pages. The filter bar keys follow the
 * Cloud Security Findings page (`filter[...]`, comma-separated); rule and
 * package are scopes set by links from other pages. */
export const APPSEC_FINDING_PARAM = {
  SEVERITY: "filter[severity__in]",
  STATE: "filter[state__in]",
  PRIORITY: "filter[priority__in]",
  TRIAGE: "filter[triage_status__in]",
  FIX: "filter[fix_available]",
  OVERDUE: "filter[overdue]",
  SUPPRESSED: "filter[suppressed]",
  TARGET: "filter[target__in]",
  APPLICATION: "filter[application__in]",
  ASSET_TYPE: "filter[target_type]",
  FIRST_SEEN: "filter[first_seen_days]",
  RULE: "rule",
  PACKAGE: "package",
  SEARCH: "filter[search]",
  SORT: "sort",
  PAGE: "page",
  PAGE_SIZE: "pageSize",
} as const;

/** Names used before the filter bar; read so old links keep working (the
 * pages redirect them to the current names). */
export const LEGACY_APPSEC_FINDING_PARAM: Record<string, string> = {
  [APPSEC_FINDING_PARAM.SEVERITY]: "severity",
  [APPSEC_FINDING_PARAM.STATE]: "state",
  [APPSEC_FINDING_PARAM.PRIORITY]: "priority",
  [APPSEC_FINDING_PARAM.TRIAGE]: "triage",
  [APPSEC_FINDING_PARAM.FIX]: "fix",
  [APPSEC_FINDING_PARAM.OVERDUE]: "overdue",
  [APPSEC_FINDING_PARAM.SUPPRESSED]: "suppressed",
  [APPSEC_FINDING_PARAM.TARGET]: "target",
  [APPSEC_FINDING_PARAM.APPLICATION]: "application",
  [APPSEC_FINDING_PARAM.SEARCH]: "q",
};

export const hasLegacyAppSecParams = (searchParams: SearchParams): boolean =>
  Object.values(LEGACY_APPSEC_FINDING_PARAM).some((name) => {
    const value = searchParams[name];
    return value !== undefined && value !== "";
  });

/** "First seen" choices (days). */
export const APPSEC_FIRST_SEEN_DAYS: readonly number[] = [1, 7, 30, 90];

export const APPSEC_PAGE_SIZE = 25;
export const APPSEC_MAX_PAGE_SIZE = 100;

export const APPSEC_FINDING_SORT = {
  PRIORITY: "-priority",
  SEVERITY: "-severity",
  NEWEST: "-first_seen_at",
  LAST_SEEN: "-last_seen_at",
  DUE: "due_at",
  RULE: "rule_id",
  PACKAGE: "pkg_name",
} as const;
export type AppSecFindingSort =
  (typeof APPSEC_FINDING_SORT)[keyof typeof APPSEC_FINDING_SORT];

export const APPSEC_FINDING_SORT_LABEL: Record<AppSecFindingSort, string> = {
  "-priority": "Priority",
  "-severity": "Severity",
  "-first_seen_at": "Newest",
  "-last_seen_at": "Last seen",
  due_at: "Due date",
  rule_id: "Rule",
  pkg_name: "Package",
};

export const APPSEC_FIX_FILTER = {
  AVAILABLE: "available",
  NONE: "none",
} as const;
export type AppSecFixFilter =
  (typeof APPSEC_FIX_FILTER)[keyof typeof APPSEC_FIX_FILTER];

export interface AppSecFindingFilters {
  severities: AppSecSeverity[];
  states: AppSecState[];
  priorities: AppSecPriority[];
  triage: string | null;
  fix: AppSecFixFilter | null;
  overdue: boolean;
  suppressed: boolean;
  target: string | null;
  application: string | null;
  rule: string | null;
  pkg: string | null;
  /** Target modes (`filter[target_type]`), e.g. repo, image, k8s. */
  assetTypes: string[];
  /** Found within the last N days. */
  firstSeenDays: number | null;
  search: string;
  sort: AppSecFindingSort;
  page: number;
  pageSize: number;
}

export const DEFAULT_APPSEC_FINDING_FILTERS: AppSecFindingFilters = {
  severities: [],
  states: [],
  priorities: [],
  triage: null,
  fix: null,
  overdue: false,
  suppressed: false,
  target: null,
  application: null,
  rule: null,
  pkg: null,
  assetTypes: [],
  firstSeenDays: null,
  search: "",
  sort: APPSEC_FINDING_SORT.PRIORITY,
  page: 1,
  pageSize: APPSEC_PAGE_SIZE,
};

const first = (value: SearchParamValue): string =>
  (Array.isArray(value) ? value[0] : value)?.trim() ?? "";

/** A parameter by its current name, else its legacy name. */
const read = (searchParams: SearchParams, name: string): string =>
  first(searchParams[name]) ||
  (LEGACY_APPSEC_FINDING_PARAM[name]
    ? first(searchParams[LEGACY_APPSEC_FINDING_PARAM[name]])
    : "");

const list = (value: string): string[] =>
  Array.from(
    new Set(
      value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  );

const csv = <T extends string>(value: string, allowed: readonly T[]): T[] => {
  const requested = list(value);
  return allowed.filter((item) => requested.includes(item));
};

const ID_PATTERN = /^[0-9a-f-]{36}$/i;

const ids = (value: string): string | null => {
  const valid = list(value).filter((item) => ID_PATTERN.test(item));
  return valid.length ? valid.join(",") : null;
};

const truthy = (value: string): boolean =>
  ["1", "true", "yes"].includes(value.toLowerCase());

const parseFix = (value: string): AppSecFixFilter | null => {
  const text = value.toLowerCase();
  if (text === "true" || text === APPSEC_FIX_FILTER.AVAILABLE) {
    return APPSEC_FIX_FILTER.AVAILABLE;
  }
  // "unavailable" comes from the shared area links (fix filter of the
  // Application Security cards).
  if (
    text === "false" ||
    text === APPSEC_FIX_FILTER.NONE ||
    text === "unavailable"
  ) {
    return APPSEC_FIX_FILTER.NONE;
  }
  return null;
};

const TARGET_MODES: readonly string[] = Object.values(TRIVY_MODE);

export const parseAppSecFindingFilters = (
  searchParams: SearchParams,
): AppSecFindingFilters => {
  const param = APPSEC_FINDING_PARAM;
  const sort = first(searchParams[param.SORT]);
  const page = Number.parseInt(first(searchParams[param.PAGE]), 10);
  const pageSize = Number.parseInt(first(searchParams[param.PAGE_SIZE]), 10);
  const days = Number.parseInt(first(searchParams[param.FIRST_SEEN]), 10);
  const triage = csv(read(searchParams, param.TRIAGE), TRIAGE_STATUS_FILTERS);
  return {
    severities: csv(read(searchParams, param.SEVERITY), APPSEC_SEVERITIES),
    states: csv(read(searchParams, param.STATE), APPSEC_STATES),
    priorities: csv(read(searchParams, param.PRIORITY), APPSEC_PRIORITIES),
    triage: triage.length ? triage.join(",") : null,
    fix: parseFix(read(searchParams, param.FIX)),
    overdue: truthy(read(searchParams, param.OVERDUE)),
    suppressed: truthy(read(searchParams, param.SUPPRESSED)),
    target: ids(read(searchParams, param.TARGET)),
    application: ids(read(searchParams, param.APPLICATION)),
    rule: first(searchParams[param.RULE]).slice(0, 200) || null,
    pkg: first(searchParams[param.PACKAGE]).slice(0, 200) || null,
    assetTypes: csv(first(searchParams[param.ASSET_TYPE]), TARGET_MODES),
    firstSeenDays: APPSEC_FIRST_SEEN_DAYS.includes(days) ? days : null,
    search: read(searchParams, param.SEARCH).slice(0, 200),
    sort: (Object.values(APPSEC_FINDING_SORT) as string[]).includes(sort)
      ? (sort as AppSecFindingSort)
      : APPSEC_FINDING_SORT.PRIORITY,
    page: Number.isFinite(page) && page > 0 ? page : 1,
    pageSize:
      Number.isFinite(pageSize) && pageSize > 0
        ? Math.min(pageSize, APPSEC_MAX_PAGE_SIZE)
        : APPSEC_PAGE_SIZE,
  };
};

/** Page URL for a workspace with the given filters (defaults are left out). */
export const appSecFindingsHref = (
  segment: AppSecSegment,
  filters: Partial<AppSecFindingFilters> = {},
): string => {
  const param = APPSEC_FINDING_PARAM;
  const merged = { ...DEFAULT_APPSEC_FINDING_FILTERS, ...filters };
  const query = new URLSearchParams();
  if (merged.severities.length)
    query.set(param.SEVERITY, merged.severities.join(","));
  if (merged.states.length) query.set(param.STATE, merged.states.join(","));
  if (merged.priorities.length)
    query.set(param.PRIORITY, merged.priorities.join(","));
  if (merged.triage) query.set(param.TRIAGE, merged.triage);
  if (merged.fix)
    query.set(
      param.FIX,
      merged.fix === APPSEC_FIX_FILTER.AVAILABLE ? "true" : "false",
    );
  if (merged.overdue) query.set(param.OVERDUE, "true");
  if (merged.suppressed) query.set(param.SUPPRESSED, "true");
  if (merged.target) query.set(param.TARGET, merged.target);
  if (merged.application) query.set(param.APPLICATION, merged.application);
  if (merged.assetTypes.length)
    query.set(param.ASSET_TYPE, merged.assetTypes.join(","));
  if (merged.firstSeenDays)
    query.set(param.FIRST_SEEN, String(merged.firstSeenDays));
  if (merged.rule) query.set(param.RULE, merged.rule);
  if (merged.pkg) query.set(param.PACKAGE, merged.pkg);
  if (merged.search) query.set(param.SEARCH, merged.search);
  if (merged.sort !== APPSEC_FINDING_SORT.PRIORITY)
    query.set(param.SORT, merged.sort);
  if (merged.pageSize !== APPSEC_PAGE_SIZE)
    query.set(param.PAGE_SIZE, String(merged.pageSize));
  if (merged.page > 1) query.set(param.PAGE, String(merged.page));
  const serialized = query.toString();
  const base = appSecurityHref(segment);
  return serialized ? `${base}?${serialized}` : base;
};

/** API query for `GET /appsec-findings` (and its summary and export). */
export const appSecFindingsQuery = (
  category: AppSecCategory | null,
  filters: AppSecFindingFilters,
  options: { paginate?: boolean } = {},
): Record<string, string> => {
  const query: Record<string, string> = {};
  if (category) query["filter[category]"] = category;
  if (filters.severities.length)
    query["filter[severity__in]"] = filters.severities.join(",");
  if (filters.states.length)
    query["filter[state__in]"] = filters.states.join(",");
  if (filters.priorities.length)
    query["filter[priority__in]"] = filters.priorities.join(",");
  if (filters.triage) query["filter[triage_status__in]"] = filters.triage;
  if (filters.fix)
    query["filter[fix_available]"] =
      filters.fix === APPSEC_FIX_FILTER.AVAILABLE ? "true" : "false";
  if (filters.overdue) query["filter[overdue]"] = "true";
  if (filters.suppressed) query["filter[suppressed]"] = "true";
  if (filters.target) query["filter[target__in]"] = filters.target;
  if (filters.application)
    query["filter[application__in]"] = filters.application;
  if (filters.assetTypes.length)
    query["filter[target_type]"] = filters.assetTypes.join(",");
  if (filters.firstSeenDays)
    query["filter[first_seen_days]"] = String(filters.firstSeenDays);
  if (filters.rule) query["filter[rule_id]"] = filters.rule;
  if (filters.pkg) query["filter[pkg_name]"] = filters.pkg;
  if (filters.search) query["filter[search]"] = filters.search;
  query.sort = filters.sort;
  if (options.paginate ?? true) {
    query["page[number]"] = String(filters.page);
    query["page[size]"] = String(filters.pageSize);
  }
  return query;
};

/**
 * Options that can match in the workspace: those in `available` (values with
 * findings there, from the summary facets) plus anything already selected, so
 * a selection never disappears from its dropdown. Without facets (an older
 * API) every option is kept.
 */
export const optionsInScope = <T extends { value: string }>(
  options: readonly T[],
  available: readonly string[] | undefined,
  selected: readonly string[] = [],
): T[] => {
  if (!available) return [...options];
  const keep = new Set([...available, ...selected]);
  return options.filter((option) => keep.has(option.value));
};

/** Comma-separated ids of a filter (target or application), as a list. */
export const selectedIds = (value: string | null): string[] =>
  value ? list(value) : [];

export const isAppSecFiltered = (filters: AppSecFindingFilters): boolean =>
  filters.severities.length > 0 ||
  filters.states.length > 0 ||
  filters.priorities.length > 0 ||
  filters.triage !== null ||
  filters.fix !== null ||
  filters.overdue ||
  filters.suppressed ||
  filters.target !== null ||
  filters.application !== null ||
  filters.rule !== null ||
  filters.pkg !== null ||
  filters.assetTypes.length > 0 ||
  filters.firstSeenDays !== null ||
  filters.search !== "";

export const toggleItem = <T>(items: readonly T[], item: T): T[] =>
  items.includes(item)
    ? items.filter((value) => value !== item)
    : [...items, item];

// --- Presentation ------------------------------------------------------------

/** Where a finding is: package and version, or file and line, or resource. */
export const appSecFindingLocation = (
  finding: Pick<
    AppSecFindingAttributes,
    | "category"
    | "pkg_name"
    | "pkg_version"
    | "file_path"
    | "start_line"
    | "resource"
    | "location"
  >,
): string => {
  if (finding.pkg_name) {
    return `${finding.pkg_name}${finding.pkg_version ? ` ${finding.pkg_version}` : ""}`;
  }
  if (finding.file_path) {
    return finding.start_line
      ? `${finding.file_path}:${finding.start_line}`
      : finding.file_path;
  }
  return finding.resource || finding.location;
};

/** What to do about a finding, in a few words, for list rows. */
export const appSecFixSummary = (
  finding: Pick<
    AppSecFindingAttributes,
    "category" | "fixed_version" | "fix_available"
  >,
): string => {
  if (finding.category !== APPSEC_CATEGORY.VULNERABILITY) return "";
  if (finding.fixed_version) return `Fix: ${finding.fixed_version}`;
  return finding.fix_available === false ? "No fix yet" : "";
};

export const formatAppSecDate = (value: string | null | undefined): string => {
  if (!value) return "–";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "–"
    : date.toISOString().slice(0, 16).replace("T", " ");
};

/** Whole days from `now` until `value`; negative when past. */
export const daysUntil = (
  value: string | null | undefined,
  now: Date = new Date(),
): number | null => {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return Math.floor((date.getTime() - now.getTime()) / 86_400_000);
};

export const dueLabel = (
  value: string | null | undefined,
  now: Date = new Date(),
): string => {
  const days = daysUntil(value, now);
  if (days === null) return "–";
  if (days < 0) return `Overdue by ${-days} d`;
  return days === 0 ? "Due today" : `Due in ${days} d`;
};

const POLICY_KIND_LABEL: Record<AppSecPolicyKind, string> = {
  rego_check: "Custom check (Rego)",
  secret_rules: "Secret rules",
  license_policy: "License policy",
  ignore_rules: "Ignore rules",
  vex: "VEX document",
};

export const APPSEC_POLICY_KINDS: readonly AppSecPolicyKind[] =
  Object.values(APPSEC_POLICY_KIND);

export const appSecPolicyKindLabel = (kind: string): string =>
  POLICY_KIND_LABEL[kind as AppSecPolicyKind] ?? titleCase(kind);

export const APPSEC_POLICY_KIND_HELP: Record<AppSecPolicyKind, string> = {
  rego_check:
    "A Rego check with a package, a METADATA block (id, title, severity) and at least one deny rule. Runs with the misconfiguration scanner.",
  secret_rules:
    "YAML with rules, allow-rules, enable-builtin-rules, disable-rules, disable-allow-rules or skip-patterns. Runs with the secret scanner.",
  license_policy:
    "YAML that lists license names under forbidden, restricted, reciprocal, notice, permissive or unencumbered, and optionally under ignored.",
  ignore_rules:
    "YAML with vulnerabilities, misconfigurations, secrets and licenses lists. Each entry has an id and may have paths, purls, expired_at and statement. Ignored findings are recorded as suppressed.",
  vex: "An OpenVEX, CSAF VEX or CycloneDX VEX document (JSON). Statements suppress vulnerabilities that do not affect the product.",
};

export const APPSEC_FEATURE_STATUS_TONE: Record<AppSecFeatureStatus, string> = {
  [APPSEC_FEATURE_STATUS.IMPLEMENTED]: "success",
  [APPSEC_FEATURE_STATUS.PARTIAL]: "warning",
  [APPSEC_FEATURE_STATUS.MISSING]: "danger",
  [APPSEC_FEATURE_STATUS.UNSUPPORTED]: "neutral",
  [APPSEC_FEATURE_STATUS.NOT_APPLICABLE]: "neutral",
};

/** Sum of the counts of the given keys. */
export const sumCounts = (
  counts: Record<string, number> | undefined,
  keys?: readonly string[],
): number =>
  Object.entries(counts ?? {}).reduce(
    (total, [key, value]) =>
      !keys || keys.includes(key) ? total + (value || 0) : total,
    0,
  );

/** `data.attributes` of a single-resource response, or `null`. */
export const attributesOf = <T>(response: unknown): T | null => {
  const data = (response as { data?: { attributes?: T } } | undefined)?.data;
  return data && !Array.isArray(data) && data.attributes
    ? data.attributes
    : null;
};

/** Message of a failed server action result, or `null` when it succeeded. */
export const actionError = (result: unknown): string | null => {
  if (!result || typeof result !== "object") return null;
  const record = result as { error?: unknown; errors?: unknown };
  if (typeof record.error === "string" && record.error) return record.error;
  if (Array.isArray(record.errors) && record.errors.length > 0) {
    const firstError = record.errors[0] as { detail?: unknown };
    return typeof firstError?.detail === "string"
      ? firstError.detail
      : "The request was rejected.";
  }
  return record.error ? "The request failed." : null;
};
