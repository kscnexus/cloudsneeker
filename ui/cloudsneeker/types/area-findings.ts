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
  };
}
