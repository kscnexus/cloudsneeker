export const CUSTODIAN_RUN_STATUS = {
  PENDING: "pending",
  RUNNING: "running",
  COMPLETED: "completed",
  FAILED: "failed",
} as const;

export type CustodianRunStatus =
  (typeof CUSTODIAN_RUN_STATUS)[keyof typeof CUSTODIAN_RUN_STATUS];

export const CUSTODIAN_RUN_TRIGGER = {
  MANUAL: "manual",
  SCHEDULED: "scheduled",
} as const;

export type CustodianRunTrigger =
  (typeof CUSTODIAN_RUN_TRIGGER)[keyof typeof CUSTODIAN_RUN_TRIGGER];

export interface CustodianPolicyAttributes {
  name: string;
  description: string;
  policy_yaml: string;
  provider_id: string;
  provider_uid?: string;
  provider_alias?: string | null;
  provider_type?: string;
  schedule_enabled?: boolean;
  schedule_cron?: string;
  schedule_timezone?: string;
  regions_override?: string[];
  next_run_at?: string | null;
  inserted_at?: string;
  updated_at?: string;
}

export interface CustodianPolicyResource {
  id: string;
  type: string;
  attributes: CustodianPolicyAttributes;
}

export interface CustodianRunDelta {
  new?: string[];
  gone?: string[];
  still_matched?: string[];
  new_count?: number;
  gone_count?: number;
  still_matched_count?: number;
}

export interface CustodianRunSummary {
  resource_count?: number;
  mode?: string;
  policies?: Array<{ name?: string; resource_count?: number; region?: string }>;
  regions?: string[];
  provider_type?: string;
  resources_preview?: Array<{
    uid?: string;
    name?: string;
    region?: string;
    type?: string;
    policy?: string;
  }>;
  delta?: CustodianRunDelta;
  prowler_check_ids?: string[];
}

export interface CustodianRunOutput {
  mode?: string;
  resource_count?: number;
  policies?: Array<{ name?: string; resource_count?: number; region?: string }>;
  resources?: Record<string, unknown>[];
  regions?: string[];
}

export interface CustodianRunAttributes {
  policy_id: string;
  provider_id: string;
  policy_name?: string;
  provider_uid?: string;
  provider_alias?: string | null;
  provider_type?: string;
  status: CustodianRunStatus;
  mode: string;
  trigger?: CustodianRunTrigger | string;
  started_at?: string | null;
  finished_at?: string | null;
  summary?: CustodianRunSummary;
  output?: CustodianRunOutput;
  error?: string;
  error_class?: string;
  triggered_by_id?: string | null;
  inserted_at?: string;
}

export interface CustodianRunResource {
  id: string;
  type: string;
  attributes: CustodianRunAttributes;
}
