// Reporting engine resources served by `cloudsneeker_api` (`/report-*`,
// `/shared-reports/<token>`). Attribute names match the API serializers.

export const REPORT_TYPE_ID = {
  EXECUTIVE: "executive",
  CLOUD_POSTURE: "cloud_posture",
  COMPLIANCE: "compliance",
  SCA: "sca",
  SAST: "sast",
  CONTAINER: "container",
  IAC: "iac",
  SECRETS: "secrets",
  GOVERNANCE: "governance",
} as const;

export type ReportTypeId = (typeof REPORT_TYPE_ID)[keyof typeof REPORT_TYPE_ID];

export const REPORT_FORMAT = {
  PDF: "pdf",
  XLSX: "xlsx",
  CSV: "csv",
  JSON: "json",
} as const;

export type ReportFormat = (typeof REPORT_FORMAT)[keyof typeof REPORT_FORMAT];

/** Formats users pick; JSON is always produced for the in-app page. */
export const SELECTABLE_REPORT_FORMATS = [
  REPORT_FORMAT.PDF,
  REPORT_FORMAT.XLSX,
  REPORT_FORMAT.CSV,
] as const;

export type SelectableReportFormat = (typeof SELECTABLE_REPORT_FORMATS)[number];

export const REPORT_RUN_STATUS = {
  PENDING: "pending",
  RUNNING: "running",
  COMPLETED: "completed",
  FAILED: "failed",
} as const;

export type ReportRunStatus =
  (typeof REPORT_RUN_STATUS)[keyof typeof REPORT_RUN_STATUS];

export const REPORT_SEVERITY = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFORMATIONAL: "informational",
} as const;

export type ReportSeverity =
  (typeof REPORT_SEVERITY)[keyof typeof REPORT_SEVERITY];

/** Most severe first, matching the API `SEVERITY_ORDER`. */
export const REPORT_SEVERITY_ORDER = [
  REPORT_SEVERITY.CRITICAL,
  REPORT_SEVERITY.HIGH,
  REPORT_SEVERITY.MEDIUM,
  REPORT_SEVERITY.LOW,
  REPORT_SEVERITY.INFORMATIONAL,
] as const;

export const SHARE_LINK_STATE = {
  ACTIVE: "active",
  EXPIRED: "expired",
  REVOKED: "revoked",
} as const;

export type ShareLinkState =
  (typeof SHARE_LINK_STATE)[keyof typeof SHARE_LINK_STATE];

export const REPORT_RESOURCE_TYPE = {
  REPORT_TYPES: "cloudsneeker-report-types",
  REPORT_RUNS: "cloudsneeker-report-runs",
  REPORT_SCHEDULES: "cloudsneeker-report-schedules",
  REPORT_SHARE_LINKS: "cloudsneeker-report-share-links",
} as const;

export interface ReportParams {
  provider_ids?: string[];
  date_from?: string | null;
  date_to?: string | null;
  severity_floor?: ReportSeverity | null;
  compliance_id?: string | null;
  scan_id?: string | null;
  trend_points?: number;
}

export interface ReportTypeAttributes {
  name: string;
  description: string;
  audience: string;
  category: string;
  formats: ReportFormat[];
  parameters: { required: string[]; optional: string[] };
}

export interface ReportTypeResource {
  type: typeof REPORT_RESOURCE_TYPE.REPORT_TYPES;
  id: string;
  attributes: ReportTypeAttributes;
}

export interface ReportRunAttributes {
  inserted_at: string;
  updated_at?: string;
  report_type: string;
  report_name: string;
  params: ReportParams;
  formats: ReportFormat[];
  available_formats: ReportFormat[];
  status: ReportRunStatus;
  trigger: string;
  error: string;
  started_at: string | null;
  finished_at: string | null;
  artifact_sizes?: Record<string, number>;
  size_bytes?: number;
  summary?: Record<string, unknown>;
  schedule_id?: string | null;
  created_by_id?: string | null;
}

export interface ReportRunResource {
  type: typeof REPORT_RESOURCE_TYPE.REPORT_RUNS;
  id: string;
  attributes: ReportRunAttributes;
}

export interface ReportScheduleAttributes {
  inserted_at?: string;
  updated_at?: string;
  name: string;
  report_type: string;
  params: ReportParams;
  formats: ReportFormat[];
  schedule_cron: string;
  schedule_timezone: string;
  recipients: string[];
  enabled: boolean;
  next_run_at?: string | null;
  last_run_at?: string | null;
  last_run_id?: string | null;
}

export interface ReportScheduleResource {
  type: typeof REPORT_RESOURCE_TYPE.REPORT_SCHEDULES;
  id: string;
  attributes: ReportScheduleAttributes;
}

export interface ReportShareLinkAttributes {
  inserted_at: string;
  report_run_id: string;
  expires_at: string;
  revoked_at: string | null;
  last_accessed_at: string | null;
  access_count: number;
  state: ShareLinkState;
  /** Only present in the create response. */
  token?: string;
}

export interface ReportShareLinkResource {
  type: typeof REPORT_RESOURCE_TYPE.REPORT_SHARE_LINKS;
  id: string;
  attributes: ReportShareLinkAttributes;
}

// Report payload (`ReportData.to_dict()` in `reports/schema.py`).

export interface ReportTrendPoint {
  date: string;
  fail: number;
  pass: number;
  critical: number;
  high: number;
}

export interface ReportRisk {
  check_id: string;
  title?: string;
  severity: string;
  findings?: number;
  resources?: number;
  service?: string;
  impact?: string;
  remediation?: string;
  [key: string]: unknown;
}

export interface ReportCompliancePosture {
  compliance_id: string;
  passed: number;
  failed: number;
  manual: number;
  total: number;
  pass_pct: number | null;
}

export interface ReportAction {
  priority: number;
  action: string;
  why?: string;
  check_id?: string;
  title?: string;
  severity?: string;
  resources?: number;
}

export type ReportCellValue = string | number | boolean | null;

export interface ReportTableColumn {
  field: string;
  header: string;
}

export interface ReportTable {
  key: string;
  title: string;
  columns: ReportTableColumn[];
  rows: Record<string, ReportCellValue>[];
  total: number;
  truncated: boolean;
}

export type ReportSourceRow = Record<string, ReportCellValue>;

export interface ReportPayload {
  report_type: string;
  title: string;
  generated_at: string;
  filters: ReportParams;
  headline: string;
  score: number | null;
  grade: string;
  kpis: Record<string, ReportCellValue>;
  severity_totals: Partial<Record<ReportSeverity, number>>;
  status_totals: { pass: number; fail: number; muted: number; manual: number };
  trend: ReportTrendPoint[];
  top_risks: ReportRisk[];
  sources: ReportSourceRow[];
  compliance: ReportCompliancePosture[];
  remediation: ReportAction[];
  tables: ReportTable[];
  empty_state: string | null;
  extra?: Record<string, unknown>;
}
