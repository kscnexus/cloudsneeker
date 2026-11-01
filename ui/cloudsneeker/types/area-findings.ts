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
}

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
