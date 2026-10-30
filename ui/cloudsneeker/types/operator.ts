// Types for plan entitlements (`/entitlements`) and the operator console
// (`/operator/*`). Keys match `cloudsneeker_api.services.plan_catalog`.

export const PLAN_FEATURE = {
  CLOUD_POSTURE: "cloud_posture",
  ATTACK_PATHS: "attack_paths",
  COMPLIANCE: "compliance",
  APPLICATION_SECURITY: "application_security",
  SAST: "sast",
  GOVERNANCE: "governance",
  REPORTS: "reports",
  REPORT_SCHEDULES: "report_schedules",
  SEEKER_AI: "seeker_ai",
  FINDING_TRIAGE: "finding_triage",
  AUDIT_LOG: "audit_log",
  SSO: "sso",
  API_ACCESS: "api_access",
  INTEGRATIONS: "integrations",
} as const;

export type PlanFeature = (typeof PLAN_FEATURE)[keyof typeof PLAN_FEATURE];

export const PLAN_LIMIT = {
  PROVIDERS: "providers",
  USERS: "users",
  APPLICATION_SECURITY_TARGETS: "application_security_targets",
  SCANS_PER_MONTH: "scans_per_month",
  REPORT_SCHEDULES: "report_schedules",
  SEEKER_AI_REQUESTS_PER_MONTH: "seeker_ai_requests_per_month",
} as const;

export type PlanLimit = (typeof PLAN_LIMIT)[keyof typeof PLAN_LIMIT];

export const SUBSCRIPTION_STATUS = {
  TRIAL: "trial",
  ACTIVE: "active",
  PAST_DUE: "past_due",
  SUSPENDED: "suspended",
  EXPIRED: "expired",
  CANCELLED: "cancelled",
} as const;

export type SubscriptionStatus =
  (typeof SUBSCRIPTION_STATUS)[keyof typeof SUBSCRIPTION_STATUS];

export const BILLING_SOURCE = {
  MANUAL: "manual",
  AWS_MARKETPLACE: "aws_marketplace",
  AZURE_MARKETPLACE: "azure_marketplace",
  SELF_HOSTED_LICENCE: "self_hosted_licence",
} as const;

export type BillingSource =
  (typeof BILLING_SOURCE)[keyof typeof BILLING_SOURCE];

export const OPERATOR_ROLE = {
  OWNER: "owner",
  SUPPORT: "support",
  BILLING: "billing",
  READ_ONLY: "read_only",
} as const;

export type OperatorRole = (typeof OPERATOR_ROLE)[keyof typeof OPERATOR_ROLE];

export const OPERATOR_CAPABILITY = {
  VIEW: "view",
  MANAGE_SUBSCRIPTIONS: "manage_subscriptions",
  SUSPEND_TENANTS: "suspend_tenants",
  MANAGE_PLANS: "manage_plans",
  VIEW_OPERATORS: "view_operators",
} as const;

export type OperatorCapability =
  (typeof OPERATOR_CAPABILITY)[keyof typeof OPERATOR_CAPABILITY];

/** Limit key -> maximum, or `null` for unlimited. */
export type PlanLimits = Partial<Record<PlanLimit, number | null>>;

/** Usage counts reported by the API (`null` when not tracked). */
export type UsageCounts = Record<string, number | null>;

export interface PlanRef {
  code: string;
  name: string;
}

export interface EntitlementsAttributes {
  plan: PlanRef;
  status: SubscriptionStatus;
  effective_status: SubscriptionStatus;
  read_only: boolean;
  features: PlanFeature[];
  limits: PlanLimits;
  usage: UsageCounts;
  over_limit: PlanLimit[];
  starts_at: string | null;
  ends_at: string | null;
  trial_ends_at: string | null;
  seats: number | null;
  billing_source: BillingSource;
}

export interface EntitlementsResource {
  type: string;
  id: string;
  attributes: EntitlementsAttributes;
}

export interface OperatorMeAttributes {
  email: string;
  name: string;
  role: OperatorRole;
  capabilities: OperatorCapability[];
}

export interface OperatorTenantAttributes {
  name: string;
  inserted_at: string | null;
  plan: string;
  plan_name: string;
  status: SubscriptionStatus;
  effective_status: SubscriptionStatus;
  read_only: boolean;
  starts_at: string | null;
  ends_at: string | null;
  trial_ends_at: string | null;
  billing_source: BillingSource;
  member_count: number;
  last_activity: string | null;
  usage: UsageCounts;
  limits: PlanLimits;
  features: PlanFeature[];
  over_limit: PlanLimit[];
}

export interface OperatorTenantResource {
  type: string;
  id: string;
  attributes: OperatorTenantAttributes;
}

export interface OperatorTenantSummary {
  total: number;
  by_status: Record<string, number>;
  by_plan: Record<string, number>;
  expiring_within_30_days: number;
  over_limit: number;
}

export interface SubscriptionAttributes {
  tenant_id: string;
  plan: string;
  plan_name: string;
  status: SubscriptionStatus;
  effective_status: SubscriptionStatus;
  read_only: boolean;
  starts_at: string | null;
  ends_at: string | null;
  trial_ends_at: string | null;
  seats: number | null;
  feature_overrides: Partial<Record<PlanFeature, boolean>>;
  limit_overrides: PlanLimits;
  billing_source: BillingSource;
  external_customer_id: string;
  notes: string;
  features: PlanFeature[];
  limits: PlanLimits;
  updated_at: string | null;
}

export interface SubscriptionChange {
  from?: unknown;
  to?: unknown;
  changed?: boolean;
}

export interface SubscriptionEventAttributes {
  tenant_id: string;
  action: string;
  source: string;
  changes: Record<string, SubscriptionChange>;
  actor_id: string | null;
  actor_email: string;
  inserted_at: string | null;
}

export interface SubscriptionEventResource {
  type: string;
  id: string;
  attributes: SubscriptionEventAttributes;
}

export interface TenantMember {
  user_id: string;
  email: string;
  name: string;
  role: string;
  date_joined: string | null;
  last_login: string | null;
}

export interface TenantScan {
  id: string;
  name: string | null;
  state: string;
  trigger: string;
  inserted_at: string | null;
  completed_at: string | null;
}

export interface OperatorTenantDetailAttributes
  extends OperatorTenantAttributes {
  subscription: SubscriptionAttributes;
  members: TenantMember[];
  recent_scans: TenantScan[];
  history: SubscriptionEventResource[];
}

export interface PlanAttributes {
  code: string;
  name: string;
  description: string;
  features: PlanFeature[];
  limits: PlanLimits;
  is_public: boolean;
  sort_order: number;
  subscriber_count?: number;
  inserted_at: string | null;
  updated_at: string | null;
}

export interface PlanResource {
  type: string;
  id: string;
  attributes: PlanAttributes;
}

export interface UsageSnapshotResource {
  type: string;
  id: string;
  attributes: { tenant_id: string; date: string; counts: UsageCounts };
}

export interface OperatorAuditAttributes {
  inserted_at: string | null;
  actor_id: string | null;
  actor_email: string;
  actor_role: string;
  action: string;
  tenant_id: string | null;
  target_type: string;
  target_id: string;
  changed_fields: string[];
  metadata: Record<string, unknown>;
  ip_address: string | null;
}

export interface OperatorAuditResource {
  type: string;
  id: string;
  attributes: OperatorAuditAttributes;
}

/** Body of `PATCH /operator/subscriptions/{tenantId}`. */
export interface SubscriptionUpdate {
  plan?: string;
  status?: SubscriptionStatus;
  starts_at?: string | null;
  ends_at?: string | null;
  trial_ends_at?: string | null;
  seats?: number | null;
  feature_overrides?: Partial<Record<PlanFeature, boolean>>;
  limit_overrides?: PlanLimits;
  billing_source?: BillingSource;
  external_customer_id?: string;
  notes?: string;
}

/** Body of `POST /operator/plans` and `PATCH /operator/plans/{code}`. */
export interface PlanWrite {
  code?: string;
  name?: string;
  description?: string;
  features?: PlanFeature[];
  limits?: PlanLimits;
  is_public?: boolean;
  sort_order?: number;
}
