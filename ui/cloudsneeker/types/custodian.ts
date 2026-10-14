export const CUSTODIAN_RUN_STATUS = {
  PENDING: "pending",
  RUNNING: "running",
  COMPLETED: "completed",
  FAILED: "failed",
} as const;

export type CustodianRunStatus =
  (typeof CUSTODIAN_RUN_STATUS)[keyof typeof CUSTODIAN_RUN_STATUS];

export interface CustodianPolicyAttributes {
  name: string;
  description: string;
  policy_yaml: string;
  provider_id: string;
  provider_uid?: string;
  provider_alias?: string | null;
  inserted_at?: string;
  updated_at?: string;
}

export interface CustodianPolicyResource {
  id: string;
  type: string;
  attributes: CustodianPolicyAttributes;
}

export interface CustodianRunSummary {
  resource_count?: number;
  mode?: string;
  policies?: Array<{ name?: string; resource_count?: number }>;
}

export interface CustodianRunAttributes {
  policy_id: string;
  provider_id: string;
  status: CustodianRunStatus;
  mode: string;
  started_at?: string | null;
  finished_at?: string | null;
  summary?: CustodianRunSummary;
  output?: Record<string, unknown>;
  error?: string;
  inserted_at?: string;
}

export interface CustodianRunResource {
  id: string;
  type: string;
  attributes: CustodianRunAttributes;
}
