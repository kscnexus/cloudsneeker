// Area findings served by `cloudsneeker_api` (`GET /area-findings`): one row
// shape for Cloud Security, Application Security and Cloud Governance.

import type { FindingTriageStatus } from "@/types/findings-triage";

export const FINDING_AREA = {
  CLOUD: "cloud",
  APPLICATION_SECURITY: "application_security",
  GOVERNANCE: "governance",
} as const;

export type FindingArea = (typeof FINDING_AREA)[keyof typeof FINDING_AREA];

export const AREA_FINDING_SOURCE_KIND = {
  PROVIDER: "provider",
  TARGET: "target",
  POLICY: "policy",
} as const;

/** Application Security finding category (one per finding). */
export const SECURITY_CATEGORY = {
  SAST: "sast",
  SCA: "sca",
  SECRETS: "secrets",
  IAC: "iac",
  CONTAINER: "container",
} as const;

export type SecurityCategory =
  (typeof SECURITY_CATEGORY)[keyof typeof SECURITY_CATEGORY];

export const SECURITY_CATEGORIES: readonly SecurityCategory[] =
  Object.values(SECURITY_CATEGORY);

/** Application Security risk priority: P0 Immediate to P4 Low. */
export const RISK_PRIORITY = {
  P0: "p0",
  P1: "p1",
  P2: "p2",
  P3: "p3",
  P4: "p4",
} as const;

export type RiskPriority = (typeof RISK_PRIORITY)[keyof typeof RISK_PRIORITY];

export const RISK_PRIORITIES: readonly RiskPriority[] =
  Object.values(RISK_PRIORITY);

/** Findings of one application (linked provider), `summary=applications`. */
export interface AreaApplicationSummary {
  id: string;
  total: number;
  critical: number;
  high: number;
  /** P0 and P1 findings. */
  urgent: number;
}

export type AreaFindingSourceKind =
  (typeof AREA_FINDING_SOURCE_KIND)[keyof typeof AREA_FINDING_SOURCE_KIND];

export interface AreaFindingAttributes {
  uid: string;
  finding_id: string | null;
  area: FindingArea;
  title: string;
  severity: string;
  status: string;
  muted: boolean;
  /** Reason of the mute rule when muted. */
  muted_reason?: string;
  /** Governance: the policy run that reported the resource. */
  run_id?: string;
  /** Governance, one-finding lookup: the resource as the run reported it. */
  resource_details?: Record<string, unknown>;
  check_id: string;
  description: string;
  status_extended: string;
  remediation: string;
  /** A concrete fix exists: a fixed version, a resolution or a recommendation. */
  fix_available: boolean;
  /** What to do, in a sentence or two ("Upgrade PyJWT from 2.8.0 to 2.10.1 or later."). */
  fix_summary: string;
  installed_version: string;
  fixed_version: string;
  fix_references: string[];
  /** EPSS: probability (0-1) the CVE is exploited in the next 30 days. */
  epss_score: number | null;
  epss_percentile: number | null;
  /** Listed in the CISA Known Exploited Vulnerabilities catalog. */
  known_exploited: boolean;
  kev_date_added: string | null;
  kev_due_date: string | null;
  kev_ransomware: boolean;
  kev_required_action: string;
  resource_id: string;
  resource_name: string;
  resource_type: string;
  location: string;
  region: string;
  service: string;
  source_kind: AreaFindingSourceKind | "";
  source_id: string;
  source_name: string;
  provider_id: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  categories: string[];
  /** Application Security only; empty in other areas. */
  security_category?: SecurityCategory | "";
  /** Application Security only; empty in other areas. */
  priority?: RiskPriority | "";
  /** Remediation due date from the priority's window. */
  due_at?: string | null;
  /** Past the due date while the triage status is still active. */
  overdue?: boolean;
  triage_id: string | null;
  triage_status: FindingTriageStatus;
  triage_notes_count: number;
  triage_latest_note: string;
  assignee_id: string | null;
  /** EB-019: set while the risk is accepted. */
  risk_reason?: string;
  risk_expires_on?: string | null;
}

export const AREA_FIX_FILTER = {
  AVAILABLE: "available",
  UNAVAILABLE: "unavailable",
} as const;

export type AreaFixFilter =
  (typeof AREA_FIX_FILTER)[keyof typeof AREA_FIX_FILTER];

export interface AreaFindingResource {
  id: string;
  type: string;
  attributes: AreaFindingAttributes;
}

export interface AreaFindingSource {
  id: string;
  name: string;
  kind: AreaFindingSourceKind;
}

export interface AreaFindingsResponse {
  data: AreaFindingResource[];
  meta?: {
    pagination?: { page: number; pages: number; count: number };
    sources?: AreaFindingSource[];
    /** Application Security: findings per category, category filter ignored. */
    category_counts?: Partial<Record<SecurityCategory, number>>;
    /** Application Security: categories some target is set up to report. */
    enabled_categories?: SecurityCategory[];
    /** Application Security: findings per priority, priority filter ignored. */
    priority_counts?: Partial<Record<RiskPriority, number>>;
    overdue_count?: number;
    applications?: AreaApplicationSummary[];
  };
}
