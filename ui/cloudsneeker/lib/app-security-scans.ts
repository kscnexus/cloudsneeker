// Security Scanning centre: every Application Security scan with URL filters
// (status, scan type, trigger, application) and small formatting helpers.

import {
  SCAN_HISTORY_VIEW,
  scanHistoryHref,
} from "@/cloudsneeker/lib/app-security-scan-history";
import {
  APP_SECURITY_SEGMENT,
  AREA_PAGE_SEGMENT,
  appSecurityHref,
} from "@/cloudsneeker/routes";
import {
  TRIVY_MODE,
  TRIVY_RUN_STATUS,
  TRIVY_RUN_TRIGGER,
  type TrivyMode,
  type TrivyRunResource,
  type TrivyRunStatus,
  type TrivyRunTrigger,
} from "@/cloudsneeker/types/trivy";

/** Scans per page in the scanning centre. */
export const SCANS_PAGE_SIZE = 25;

/** Short scan type names for tables, chips and filters. */
export const SCAN_TYPE_LABEL: Record<TrivyMode, string> = {
  [TRIVY_MODE.REPO]: "Code repository",
  [TRIVY_MODE.FS]: "Filesystem",
  [TRIVY_MODE.ROOTFS]: "Root filesystem archive",
  [TRIVY_MODE.IMAGE]: "Container image",
  [TRIVY_MODE.IAC]: "Infrastructure as code",
  [TRIVY_MODE.SBOM]: "SBOM",
  [TRIVY_MODE.K8S]: "Kubernetes",
  [TRIVY_MODE.SAST]: "Static analysis",
};

export const SCAN_TYPES: readonly TrivyMode[] = Object.values(TRIVY_MODE);

export const SCAN_STATUSES: readonly TrivyRunStatus[] =
  Object.values(TRIVY_RUN_STATUS);

export const SCAN_TRIGGERS: readonly TrivyRunTrigger[] =
  Object.values(TRIVY_RUN_TRIGGER);

export const SCAN_TRIGGER_LABEL: Record<TrivyRunTrigger, string> = {
  [TRIVY_RUN_TRIGGER.MANUAL]: "Manual",
  [TRIVY_RUN_TRIGGER.SCHEDULED]: "Scheduled",
};

const isScanType = (value: string): value is TrivyMode =>
  (SCAN_TYPES as readonly string[]).includes(value);

const isScanStatus = (value: string): value is TrivyRunStatus =>
  (SCAN_STATUSES as readonly string[]).includes(value);

const isScanTrigger = (value: string): value is TrivyRunTrigger =>
  (SCAN_TRIGGERS as readonly string[]).includes(value);

/** Short label for a target mode; the raw value when unknown, a dash if empty. */
export const scanTypeLabel = (mode: string | undefined): string => {
  if (!mode) return "—";
  return isScanType(mode) ? SCAN_TYPE_LABEL[mode] : mode;
};

export const scanTriggerLabel = (trigger: string | undefined): string => {
  if (!trigger) return "—";
  return isScanTrigger(trigger) ? SCAN_TRIGGER_LABEL[trigger] : trigger;
};

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Provider (application) ids are UUIDs; the API rejects anything else. */
export const isApplicationId = (value: string | undefined): value is string =>
  Boolean(value && UUID_PATTERN.test(value));

/** URL query names of the scanning centre. */
export const SCAN_FILTER_PARAM = {
  STATUS: "status",
  TYPE: "type",
  TRIGGER: "trigger",
  APPLICATION: "app",
  PAGE: "page",
} as const;

type QueryValue = string | string[] | undefined;

const first = (value: QueryValue): string | undefined =>
  (Array.isArray(value) ? value[0] : value)?.trim() || undefined;

export interface ScanFilters {
  status?: TrivyRunStatus;
  mode?: TrivyMode;
  trigger?: TrivyRunTrigger;
  application?: string;
  page: number;
}

export const parsePage = (value: QueryValue): number => {
  const page = Number.parseInt(first(value) ?? "", 10);
  return Number.isFinite(page) && page >= 1 ? page : 1;
};

/** Filters from the URL; unknown values are dropped, not sent to the API. */
export const parseScanFilters = (
  searchParams: Record<string, QueryValue>,
): ScanFilters => {
  const status = first(searchParams[SCAN_FILTER_PARAM.STATUS]);
  const mode = first(searchParams[SCAN_FILTER_PARAM.TYPE]);
  const trigger = first(searchParams[SCAN_FILTER_PARAM.TRIGGER]);
  const application = first(searchParams[SCAN_FILTER_PARAM.APPLICATION]);
  return {
    status: status && isScanStatus(status) ? status : undefined,
    mode: mode && isScanType(mode) ? mode : undefined,
    trigger: trigger && isScanTrigger(trigger) ? trigger : undefined,
    application: isApplicationId(application) ? application : undefined,
    page: parsePage(searchParams[SCAN_FILTER_PARAM.PAGE]),
  };
};

/** `/trivy-runs` query for the filters: current scans, newest first. */
export const scanRunsQuery = (
  filters: ScanFilters,
  pageSize: number = SCANS_PAGE_SIZE,
): Record<string, string> => {
  const query: Record<string, string> = {
    "filter[archived]": "false",
    sort: "-inserted_at",
    "page[size]": String(pageSize),
    "page[number]": String(filters.page),
  };
  if (filters.status) query["filter[status]"] = filters.status;
  if (filters.mode) query["filter[mode]"] = filters.mode;
  if (filters.trigger) query["filter[trigger]"] = filters.trigger;
  if (filters.application) query["filter[provider]"] = filters.application;
  return query;
};

/** Scanning centre URL; filters merge over `filters` and page resets to 1. */
export const scansHref = (
  filters: Partial<ScanFilters> = {},
  overrides: Partial<ScanFilters> = {},
): string => {
  const merged: Partial<ScanFilters> = {
    ...filters,
    page: 1,
    ...overrides,
  };
  const params = new URLSearchParams();
  if (merged.status) params.set(SCAN_FILTER_PARAM.STATUS, merged.status);
  if (merged.mode) params.set(SCAN_FILTER_PARAM.TYPE, merged.mode);
  if (merged.trigger) params.set(SCAN_FILTER_PARAM.TRIGGER, merged.trigger);
  if (merged.application) {
    params.set(SCAN_FILTER_PARAM.APPLICATION, merged.application);
  }
  if (merged.page && merged.page > 1) {
    params.set(SCAN_FILTER_PARAM.PAGE, String(merged.page));
  }
  const query = params.toString();
  const base = appSecurityHref(APP_SECURITY_SEGMENT.SCANS);
  return query ? `${base}?${query}` : base;
};

/** Archived scans live on the hub's Scans tab. */
export const archivedScansHref = (): string =>
  scanHistoryHref(SCAN_HISTORY_VIEW.ARCHIVED);

/** Findings page filtered to one application. */
export const applicationFindingsHref = (
  applicationId: string,
  extra: Record<string, string> = {},
): string => {
  const params = new URLSearchParams({ app: applicationId, ...extra });
  return `${appSecurityHref(AREA_PAGE_SEGMENT.FINDINGS)}?${params.toString()}`;
};

const parseTime = (value: string | null | undefined): number | null => {
  if (!value) return null;
  const time = Date.parse(value);
  return Number.isNaN(time) ? null : time;
};

/** Run time in ms; running scans count up to `now`; null when not started. */
export const runDurationMs = (
  run: TrivyRunResource,
  now: number = Date.now(),
): number | null => {
  const started = parseTime(run.attributes.started_at);
  if (started === null) return null;
  const finished = parseTime(run.attributes.finished_at);
  const end =
    finished ??
    (run.attributes.status === TRIVY_RUN_STATUS.RUNNING ? now : null);
  if (end === null || end < started) return null;
  return end - started;
};

const pad = (value: number): string => String(value).padStart(2, "0");

/** "850ms" is shown as "<1s"; then "42s", "3m 05s", "1h 02m". */
export const formatDuration = (ms: number | null): string => {
  if (ms === null || !Number.isFinite(ms) || ms < 0) return "—";
  const seconds = Math.floor(ms / 1000);
  if (seconds < 1) return "<1s";
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${pad(seconds % 60)}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${pad(minutes % 60)}m`;
};

export const formatRunTime = (value: string | null | undefined): string => {
  const time = parseTime(value);
  return time === null ? "—" : new Date(time).toLocaleString();
};

/** Findings the scan reported, when its summary has a count. */
export const runFindingCount = (run: TrivyRunResource): number | null => {
  const count = run.attributes.summary?.finding_count;
  return typeof count === "number" && Number.isFinite(count) ? count : null;
};

/** First line of an error, cut to `max` characters. */
export const errorSnippet = (
  error: string | undefined,
  max: number = 120,
): string => {
  const line = (error ?? "").trim().split(/\r?\n/)[0] ?? "";
  return line.length > max ? `${line.slice(0, max - 1).trimEnd()}…` : line;
};
