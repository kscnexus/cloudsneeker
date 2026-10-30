// Audit log resources served by `cloudsneeker_api` (`/audit-events`).
// Attribute names match `AuditEventSerializer`.

export const AUDIT_EVENT_RESOURCE_TYPE = "cloudsneeker-audit-events" as const;

export const AUDIT_OUTCOME = {
  SUCCESS: "success",
  FAILURE: "failure",
} as const;

export type AuditOutcome = (typeof AUDIT_OUTCOME)[keyof typeof AUDIT_OUTCOME];

export interface AuditEventAttributes {
  inserted_at: string;
  actor_id: string | null;
  actor_email: string;
  action: string;
  target_type: string;
  target_id: string;
  target_label: string;
  outcome: AuditOutcome;
  status_code: number | null;
  ip_address: string | null;
  user_agent: string;
  request_id: string;
  method: string;
  path: string;
  metadata: Record<string, unknown>;
}

export interface AuditEventResource {
  type: typeof AUDIT_EVENT_RESOURCE_TYPE;
  id: string;
  attributes: AuditEventAttributes;
}
