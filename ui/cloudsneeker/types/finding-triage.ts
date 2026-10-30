// Finding triage resources served by `cloudsneeker_api` (EB-010). Status
// values and labels come from the inherited `@/types/findings-triage`.

import type { FindingTriageStatus } from "@/types/findings-triage";

export const FINDING_TRIAGE_RESOURCE_TYPE = {
  TRIAGE: "cloudsneeker-finding-triages",
  LOOKUP: "cloudsneeker-finding-triage-lookups",
} as const;

export interface FindingTriageAttributes {
  finding_uid: string;
  finding_id: string | null;
  status: FindingTriageStatus;
  stored_status: FindingTriageStatus | null;
  status_changed_at: string | null;
  updated_at: string;
  source: string;
  check_id: string;
  provider_id: string | null;
  assignee_id: string | null;
  updated_by_id: string | null;
  raw_finding_status: string | null;
  triage_notes_count: number;
  has_note: boolean;
  note_id: string | null;
  current_note: string;
}

export interface FindingTriageResource {
  id: string;
  type: string;
  attributes: FindingTriageAttributes;
}

export interface FindingTriageLookupAttributes {
  finding_id: string;
  finding_uid: string;
  triage_id: string;
  triage_status: FindingTriageStatus;
  triage_notes_count: number;
  triage_has_note: boolean;
  assignee_id: string | null;
}

export interface FindingTriageLookupResource {
  id: string;
  type: string;
  attributes: FindingTriageLookupAttributes;
}
