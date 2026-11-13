export const TRIVY_MODE = {
  IAC: "iac",
  IMAGE: "image",
  FS: "fs",
  REPO: "repo",
  SBOM: "sbom",
  K8S: "k8s",
  SAST: "sast",
  ROOTFS: "rootfs",
} as const;

/** Trivy scanners accepted by `normalize_scanners` (`services/trivy.py`). */
export const TRIVY_SCANNER = {
  VULN: "vuln",
  MISCONFIG: "misconfig",
  SECRET: "secret",
  LICENSE: "license",
  RBAC: "rbac",
} as const;

export type TrivyScanner = (typeof TRIVY_SCANNER)[keyof typeof TRIVY_SCANNER];

/** Rule packs accepted by `validate_sast_config` (`services/sast.py`). */
export const SAST_RULESET = {
  AUTO: "auto",
  ALL: "all",
  CSHARP: "csharp",
  GO: "go",
  JAVA: "java",
  JAVASCRIPT: "javascript",
  PYTHON: "python",
  SCALA: "scala",
} as const;

export type SastRuleset = (typeof SAST_RULESET)[keyof typeof SAST_RULESET];

export type TrivyMode = (typeof TRIVY_MODE)[keyof typeof TRIVY_MODE];

export const TRIVY_RUN_STATUS = {
  PENDING: "pending",
  RUNNING: "running",
  COMPLETED: "completed",
  FAILED: "failed",
  CANCELLED: "cancelled",
} as const;

export type TrivyRunStatus =
  (typeof TRIVY_RUN_STATUS)[keyof typeof TRIVY_RUN_STATUS];

export const TRIVY_RUN_TRIGGER = {
  MANUAL: "manual",
  SCHEDULED: "scheduled",
} as const;

export type TrivyRunTrigger =
  (typeof TRIVY_RUN_TRIGGER)[keyof typeof TRIVY_RUN_TRIGGER];

export interface TrivyTargetConfig {
  scanners?: string[];
  severity?: string[] | string;
  images?: string[];
  image?: string;
  repository_url?: string;
  /** Branch a repository or static analysis target scans; empty = default. */
  branch?: string;
  url?: string;
  path?: string;
  archive_b64?: string;
  sbom?: string;
  namespace?: string;
  context?: string;
  rulesets?: string[];
  exclude?: string[];
  /** `builtin:<key>` or a scan profile id. */
  profile?: string;
  /** Scan options that override the profile. */
  options?: Record<string, unknown>;
}

export interface TrivyTargetAttributes {
  name: string;
  description: string;
  mode: TrivyMode;
  config: TrivyTargetConfig;
  provider_id: string;
  provider_uid?: string;
  provider_alias?: string | null;
  provider_type?: string;
  schedule_enabled?: boolean;
  schedule_cron?: string;
  schedule_timezone?: string;
  next_run_at?: string | null;
  inserted_at?: string;
  updated_at?: string;
  application_id?: string | null;
  application_name?: string | null;
}

export interface TrivyTargetResource {
  id: string;
  type: string;
  attributes: TrivyTargetAttributes;
}

export interface TrivyRunSummary {
  mode?: string;
  path?: string;
  scan_id?: string;
  finding_count?: number | null;
  sbom_id?: string | null;
  partial?: boolean;
  /** Branch the run scanned (Git targets). */
  branch?: string;
}

export interface TrivyRunCoverage {
  categories?: string[];
  severities?: string[] | null;
  fixed_only?: boolean;
  complete?: boolean;
  reasons?: string[];
}

export interface TrivyRunLifecycle {
  new?: number;
  reopened?: number;
  open?: number;
  fixed?: number;
  suppressed?: number;
}

export interface TrivyRunStats {
  total?: number;
  suppressed?: number;
  by_category?: Record<string, Record<string, number>>;
  lifecycle?: TrivyRunLifecycle;
  components?: number;
  passed_checks?: number;
  units?: number;
  failed_units?: number;
}

export interface TrivyRunAttributes {
  target_id: string;
  target_name?: string;
  target_mode?: string;
  provider_id: string;
  provider_uid?: string;
  status: TrivyRunStatus;
  trigger: TrivyRunTrigger;
  started_at?: string | null;
  finished_at?: string | null;
  scan_id?: string | null;
  summary?: TrivyRunSummary;
  output?: Record<string, unknown>;
  error?: string;
  error_class?: string;
  /** Set once the run is past the one-year history window. */
  archived_at?: string | null;
  inserted_at?: string;
  updated_at?: string;
  engine?: string;
  engine_version?: string;
  profile_ref?: string;
  options?: Record<string, unknown>;
  command?: string[];
  exit_code?: number | null;
  stderr_tail?: string;
  duration_ms?: number | null;
  attempts?: number;
  database?: Record<string, unknown>;
  coverage?: TrivyRunCoverage;
  stats?: TrivyRunStats;
  cancel_requested_at?: string | null;
  has_artifact?: boolean;
  /** Branch the run scanned; empty when unknown or not a Git target. */
  branch?: string;
}

/** One branch of a code repository source. */
export interface RepositoryBranchAttributes {
  name: string;
  /** The repository's default branch (remote HEAD). */
  default: boolean;
}

export interface RepositoryBranchResource {
  id: string;
  type: string;
  attributes: RepositoryBranchAttributes;
}

/** Branches of a source, default branch first. */
export interface RepositoryBranchList {
  branches: string[];
  defaultBranch: string;
  truncated: boolean;
}

export interface TrivyRunResource {
  id: string;
  type: string;
  attributes: TrivyRunAttributes;
}
