// Application security posture management (ASPM) API resources
// (`/api/v1/appsec-*`, served by `cloudsneeker_api/views_appsec.py`).

export const APPSEC_CATEGORY = {
  VULNERABILITY: "vulnerability",
  MISCONFIGURATION: "misconfiguration",
  SECRET: "secret",
  LICENSE: "license",
  CODE: "code",
} as const;
export type AppSecCategory =
  (typeof APPSEC_CATEGORY)[keyof typeof APPSEC_CATEGORY];

export const APPSEC_SEVERITY = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFORMATIONAL: "informational",
  UNKNOWN: "unknown",
} as const;
export type AppSecSeverity =
  (typeof APPSEC_SEVERITY)[keyof typeof APPSEC_SEVERITY];

export const APPSEC_STATE = {
  NEW: "new",
  OPEN: "open",
  REOPENED: "reopened",
  FIXED: "fixed",
} as const;
export type AppSecState = (typeof APPSEC_STATE)[keyof typeof APPSEC_STATE];

export const APPSEC_PRIORITY = {
  URGENT: "urgent",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
} as const;
export type AppSecPriority =
  (typeof APPSEC_PRIORITY)[keyof typeof APPSEC_PRIORITY];

export const APPSEC_POLICY_KIND = {
  REGO_CHECK: "rego_check",
  SECRET_RULES: "secret_rules",
  LICENSE_POLICY: "license_policy",
  IGNORE_RULES: "ignore_rules",
  VEX: "vex",
} as const;
export type AppSecPolicyKind =
  (typeof APPSEC_POLICY_KIND)[keyof typeof APPSEC_POLICY_KIND];

export const APPSEC_FEATURE_STATUS = {
  IMPLEMENTED: "implemented",
  PARTIAL: "partial",
  MISSING: "missing",
  UNSUPPORTED: "unsupported",
  NOT_APPLICABLE: "not_applicable",
} as const;
export type AppSecFeatureStatus =
  (typeof APPSEC_FEATURE_STATUS)[keyof typeof APPSEC_FEATURE_STATUS];

export interface AppSecResource<T> {
  type: string;
  id: string;
  attributes: T;
}

export interface AppSecPriorityFactor {
  key: string;
  label: string;
  points: number;
  value?: unknown;
}

export interface AppSecFindingAttributes {
  uid: string;
  category: AppSecCategory;
  finding_type: string;
  scanner: string;
  title: string;
  severity: AppSecSeverity;
  source_severity: string;
  priority: AppSecPriority;
  priority_score: number;
  state: AppSecState;
  triage_status: string;
  rule_id: string;
  pkg_name: string;
  pkg_version: string;
  fixed_version: string;
  ecosystem: string;
  location: string;
  file_path: string;
  start_line: number | null;
  end_line: number | null;
  resource: string;
  cvss_score: number | null;
  fix_available: boolean | null;
  suppressed: boolean;
  first_seen_at: string | null;
  last_seen_at: string | null;
  fixed_at: string | null;
  due_at: string | null;
  reopen_count: number;
  target_id: string;
  target_name: string;
  target_type: string;
  application_id: string | null;
  application_name: string | null;
}

export interface AppSecFindingEvent {
  kind: string;
  at: string | null;
  run_id: string | null;
  detail: Record<string, unknown>;
}

export interface AppSecCodeLine {
  number: number | null;
  content: string;
  is_cause: boolean;
}

export interface AppSecRelatedFindings {
  same_rule_total: number;
  same_rule: AppSecResource<AppSecFindingAttributes>[];
  same_package_total: number;
  same_package: AppSecResource<AppSecFindingAttributes>[];
}

export interface AppSecRecentScan {
  id: string;
  status: string;
  at: string | null;
  engine_version: string;
}

export interface AppSecFindingDetailAttributes extends AppSecFindingAttributes {
  description: string;
  purl: string;
  primary_url: string;
  epss_score: number | null;
  known_exploited: boolean | null;
  suppression: Record<string, string>;
  priority_factors: AppSecPriorityFactor[];
  details: Record<string, unknown>;
  first_run_id: string | null;
  last_run_id: string | null;
  triage_id: string | null;
  events: AppSecFindingEvent[];
  related: AppSecRelatedFindings;
  recent_scans: AppSecRecentScan[];
}

export interface AppSecVulnerabilityMetrics {
  instances: number;
  unique_ids: number;
  affected_packages: number;
  fixable: number;
  unfixed: number;
}

export interface AppSecFindingsSummary {
  active: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  by_priority: Record<string, number>;
  by_state: Record<string, number>;
  by_triage_status: Record<string, number>;
  suppressed: number;
  overdue: number;
  vulnerabilities: AppSecVulnerabilityMetrics;
}

export interface AppSecTrendPoint {
  date: string;
  detected: number;
  fixed: number;
  scans: number;
  failed_scans: number;
}

export interface AppSecTopTarget {
  target_id: string;
  name: string;
  target_type: string;
  application: string | null;
  total: number;
  critical: number;
  high: number;
  urgent: number;
  top_score: number | null;
}

export interface AppSecTopPackage {
  pkg_name: string;
  ecosystem: string;
  vulnerabilities: number;
  targets: number;
  critical: number;
  high: number;
}

export interface AppSecOverviewInventory {
  applications: number;
  targets: number;
  scanned_targets: number;
  targets_by_type: Record<string, number>;
  unassigned_targets: number;
}

export interface AppSecOverviewLastScan {
  id: string;
  status: string;
  at: string;
}

export interface AppSecOverviewScans {
  total: number;
  by_status: Record<string, number>;
  last: AppSecOverviewLastScan | null;
}

export interface AppSecOverviewComponents {
  total: number;
  vulnerable: number;
  by_ecosystem: Record<string, number>;
  targets_with_sbom: number;
}

export interface AppSecOverview {
  generated_at: string;
  window_days: number;
  inventory: AppSecOverviewInventory;
  scans: AppSecOverviewScans;
  findings: AppSecFindingsSummary;
  fixed_in_window: number;
  mean_days_to_fix: number | null;
  components: AppSecOverviewComponents;
  trend: AppSecTrendPoint[];
  top_targets: AppSecTopTarget[];
  top_packages: AppSecTopPackage[];
}

export interface AppSecApplicationAsset {
  id: string;
  name: string;
  target_type: string;
  provider_uid: string;
  schedule_enabled: boolean;
  active_findings: number;
  critical: number;
  high: number;
}

export interface AppSecApplicationAttributes {
  name: string;
  description: string;
  owner: string;
  criticality: string;
  environment: string;
  internet_exposed: boolean | null;
  tags: string[];
  default_profile_ref: string;
  inserted_at: string | null;
  updated_at: string | null;
  targets?: number;
  target_types?: string[];
  active_findings?: number;
  critical?: number;
  high?: number;
  urgent?: number;
  risk_score?: number;
  last_scan_at?: string | null;
  last_scan_status?: string | null;
  sbom_targets?: number;
  assets?: AppSecApplicationAsset[];
}

export interface AppSecProfileAttributes {
  ref: string;
  builtin: boolean;
  name: string;
  description: string;
  target_types: string[];
  options: Record<string, unknown>;
  enabled: boolean;
  inserted_at: string | null;
  updated_at: string | null;
}

export interface AppSecPolicyValidation {
  valid?: boolean;
  errors?: string[];
  warnings?: string[];
  info?: Record<string, unknown>;
}

export interface AppSecPolicyVersion {
  version: number;
  inserted_at: string | null;
  content: string;
}

export interface AppSecPolicyAttributes {
  kind: AppSecPolicyKind;
  name: string;
  description: string;
  enabled: boolean;
  version: number;
  validation: AppSecPolicyValidation;
  inserted_at: string | null;
  updated_at: string | null;
  content?: string;
  versions?: AppSecPolicyVersion[];
}

export interface AppSecSbomSummary {
  total?: number;
  ecosystems?: Record<string, number>;
  licenses?: Record<string, number>;
  relationships?: Record<string, number>;
  without_license?: number;
  vulnerable?: number;
  distinct_packages?: number;
}

export interface AppSecSbomVersion {
  id: string;
  version: number;
  inserted_at: string | null;
  component_count: number;
  vulnerability_count: number;
}

export interface AppSecSbomAttributes {
  target_id: string;
  target_name: string;
  target_type: string;
  application_id: string | null;
  application_name: string | null;
  run_id: string | null;
  source: string;
  document_format: string;
  version: number;
  artifact_name: string;
  artifact_type: string;
  component_count: number;
  vulnerable_component_count: number;
  vulnerability_count: number;
  summary: AppSecSbomSummary;
  inserted_at: string | null;
  versions?: AppSecSbomVersion[];
  download_formats?: string[];
}

export interface AppSecComponentAttributes {
  sbom_id: string;
  target_id: string;
  target_name: string;
  name: string;
  version: string;
  ecosystem: string;
  package_class: string;
  purl: string;
  licenses: string[];
  relationship: string;
  dev: boolean;
  location: string;
  depends_on: string[];
  vulnerability_count: number;
  max_severity: string;
  fixed_version: string;
}

export interface AppSecDiffRow {
  name: string;
  ecosystem: string;
  location: string;
  purl: string;
  licenses: string[];
  versions?: string[];
  from_versions?: string[];
  to_versions?: string[];
}

export interface AppSecSbomRef {
  id: string;
  version: number;
  inserted_at: string | null;
}

export interface AppSecDiffCounts {
  added: number;
  removed: number;
  changed: number;
  unchanged: number;
}

export interface AppSecSbomComparison {
  base: AppSecSbomRef;
  head: AppSecSbomRef;
  counts: AppSecDiffCounts;
  added: AppSecDiffRow[];
  removed: AppSecDiffRow[];
  changed: AppSecDiffRow[];
  truncated: boolean;
}

export interface AppSecCapabilityTarget {
  id: string;
  label: string;
  experimental: boolean;
  scanners: string[];
  default_scanners: string[];
  options: string[];
  export_formats: string[];
  notes: string[];
}

export interface AppSecOptionSpec {
  type: string;
  label: string;
  help?: string;
  choices?: string[];
  min?: number;
  max?: number;
  scanner?: string;
  default?: unknown;
}

export interface AppSecCapabilityFeature {
  area: string;
  feature: string;
  status: AppSecFeatureStatus;
  status_label: string;
  detail: string;
}

export interface AppSecLabelled {
  id: string;
  label: string;
}

export interface AppSecUnavailableTarget extends AppSecLabelled {
  status: string;
  reason: string;
}

export interface AppSecBuiltinProfile {
  ref: string;
  name: string;
  description: string;
  target_types: string[];
  options: Record<string, unknown>;
}

export interface AppSecCapabilities {
  engine_version: string;
  scanners: AppSecLabelled[];
  targets: AppSecCapabilityTarget[];
  unavailable_targets: AppSecUnavailableTarget[];
  other_engine_targets: AppSecLabelled[];
  options: Record<string, AppSecOptionSpec>;
  license_categories: string[];
  builtin_profiles: AppSecBuiltinProfile[];
  default_profile_ref: string;
  features: AppSecCapabilityFeature[];
}

export interface AppSecEngineInfo {
  available: boolean;
  version: string;
  pinned_version: string;
  matches_pin: boolean;
  vulnerability_db: Record<string, unknown> | null;
  java_db: Record<string, unknown> | null;
  check_bundle: Record<string, unknown> | null;
  error: string;
}

export interface AppSecEngineQueue {
  pending: number;
  running: number;
}

export interface AppSecEngineRecent {
  total: number;
  by_status: Record<string, number>;
  by_failure: Record<string, number>;
}

export interface AppSecEngineStatus {
  engine: AppSecEngineInfo;
  vulnerability_database: Record<string, unknown>;
  limits: Record<string, number>;
  direct_target_types: string[];
  queue: AppSecEngineQueue;
  last_7_days: AppSecEngineRecent;
}

export interface AppSecRetention {
  sbom_versions: number;
  raw_artifact_days: number;
  fixed_findings_days: number;
}

export interface AppSecSettings {
  risk: Record<string, unknown>;
  risk_overrides: Record<string, unknown>;
  risk_defaults: Record<string, unknown>;
  sla_days: Record<string, number>;
  sla_defaults: Record<string, number>;
  retention: AppSecRetention;
  default_profiles: Record<string, string>;
  updated_at: string | null;
}
