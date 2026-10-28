export const TRIVY_MODE = {
  IAC: "iac",
  IMAGE: "image",
  FS: "fs",
  REPO: "repo",
  SBOM: "sbom",
  K8S: "k8s",
} as const;

export type TrivyMode = (typeof TRIVY_MODE)[keyof typeof TRIVY_MODE];

export const TRIVY_RUN_STATUS = {
  PENDING: "pending",
  RUNNING: "running",
  COMPLETED: "completed",
  FAILED: "failed",
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
  url?: string;
  path?: string;
  archive_b64?: string;
  sbom?: string;
  namespace?: string;
  context?: string;
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
  inserted_at?: string;
  updated_at?: string;
}

export interface TrivyRunResource {
  id: string;
  type: string;
  attributes: TrivyRunAttributes;
}
