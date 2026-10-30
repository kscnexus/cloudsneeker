// Audit log page helpers: human labels for recorded actions, page filters to
// API query params, and the CSV export link. Action names come from
// `cloudsneeker_api/audit.py` (`<namespace>.<verb>`); engine names in them
// never reach the screen.

import { BRAND } from "@/cloudsneeker/brand";
import { AUDIT_LOG_EXPORT_API, PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import { AUDIT_OUTCOME, type AuditOutcome } from "@/cloudsneeker/types/audit";

export const AUDIT_PAGE_SIZE = 50;

/** Filter categories offered on the page, each an action prefix. */
export const AUDIT_ACTION_CATEGORY = {
  AUTH: "auth",
  USER: "user",
  ROLE: "role",
  MEMBERSHIP: "membership",
  INVITATION: "invitation",
  PROVIDER: "provider",
  PROVIDER_SECRET: "provider_secret",
  INTEGRATION: "integration",
  MUTE_RULE: "mute_rule",
  SCAN: "scan",
  REPORT: "report",
  REPORT_SCHEDULE: "report_schedule",
  API_KEY: "api_key",
  EMAIL_CONFIG: "email_config",
  GOVERNANCE: "custodian_policy",
  APP_SECURITY: "trivy_target",
  AUDIT_LOG: "audit_log",
} as const;

export type AuditActionCategory =
  (typeof AUDIT_ACTION_CATEGORY)[keyof typeof AUDIT_ACTION_CATEGORY];

/** Display name of each action namespace (and filter category). */
const NAMESPACE_LABEL: Record<string, string> = {
  auth: "Sign-in",
  user: "user",
  "user.roles": "user roles",
  tenant: "organization",
  role: "role",
  "role.provider_groups": "role provider groups",
  membership: "membership",
  invitation: "invitation",
  provider: "provider",
  provider_group: "provider group",
  "provider_group.providers": "provider group members",
  provider_secret: "provider credentials",
  integration: "integration",
  "integration.slack_connect": "Slack connection",
  processor: "processor",
  saml_config: "SSO configuration",
  lighthouse_config: `${BRAND.assistantName} settings`,
  mute_rule: "mute rule",
  scan: "scan",
  scan_schedule: "scan schedule",
  scan_profile: "scan profile",
  task: "task",
  finding: "finding",
  finding_triage: "finding triage",
  report: "report",
  "report.share_link": "report share link",
  report_schedule: "report schedule",
  api_key: "API key",
  email_config: "email delivery settings",
  slack_app_config: "Slack app settings",
  alert_rule: "alert rule",
  alert_recipient: "alert recipient",
  ingestion: "CLI import",
  custodian_policy: `${BRAND.governanceName} policy`,
  custodian_run: `${BRAND.governanceName} run`,
  trivy_target: `${BRAND.appSecurityName} target`,
  trivy_run: `${BRAND.appSecurityName} scan`,
  audit_log: "audit log",
};

const CATEGORY_LABEL: Record<AuditActionCategory, string> = {
  auth: "Sign-in",
  user: "Users",
  role: "Roles",
  membership: "Memberships",
  invitation: "Invitations",
  provider: "Providers",
  provider_secret: "Provider credentials",
  integration: "Integrations",
  mute_rule: "Mute rules",
  scan: "Scans",
  report: "Reports",
  report_schedule: "Report schedules",
  api_key: "API keys",
  email_config: "Email delivery",
  custodian_policy: BRAND.governanceName,
  trivy_target: BRAND.appSecurityName,
  audit_log: "Audit log",
};

export const AUDIT_CATEGORY_OPTIONS = Object.values(AUDIT_ACTION_CATEGORY).map(
  (value) => ({ value, label: CATEGORY_LABEL[value] }),
);

const VERB_LABEL: Record<string, string> = {
  create: "Created",
  update: "Updated",
  delete: "Deleted",
  add: "Added",
  remove: "Removed",
  revoke: "Revoked",
  accept: "Accepted",
  export: "Exported",
  connection_test: "Tested connection of",
};

/** Whole-action labels where "<verb> <namespace>" reads badly. */
const ACTION_LABEL: Record<string, string> = {
  "auth.sign_in": "Signed in",
  "auth.sign_in_failed": "Sign-in failed",
  "auth.switch_tenant": "Switched organization",
  "scan.launch": "Launched scan",
  "report.generate": "Generated report",
  "integration.jira_dispatch": "Sent findings to Jira",
  "integration.slack_connect": "Connected Slack",
};

const humanize = (value: string): string =>
  value.replace(/[._-]+/g, " ").trim();

const capitalize = (value: string): string =>
  value ? value[0].toUpperCase() + value.slice(1) : value;

/** "provider.delete" -> "Deleted provider"; unknown names stay readable. */
export const auditActionLabel = (action: string): string => {
  if (!action) return "Unknown action";
  if (ACTION_LABEL[action]) return ACTION_LABEL[action];
  const split = action.lastIndexOf(".");
  if (split <= 0) return capitalize(humanize(action));
  const namespace = action.slice(0, split);
  const verb = action.slice(split + 1);
  const subject = NAMESPACE_LABEL[namespace] ?? humanize(namespace);
  const verbLabel = VERB_LABEL[verb];
  if (verbLabel) return `${verbLabel} ${subject}`;
  return capitalize(`${subject}: ${humanize(verb)}`);
};

/** Display name of a target type ("provider_secret" -> "provider credentials"). */
export const auditTargetTypeLabel = (targetType: string): string =>
  capitalize(NAMESPACE_LABEL[targetType] ?? humanize(targetType));

export const auditOutcomeLabel = (outcome: string): string =>
  outcome === AUDIT_OUTCOME.SUCCESS
    ? "Success"
    : outcome === AUDIT_OUTCOME.FAILURE
      ? "Failure"
      : "Unknown";

export const auditOutcomeVariant = (outcome: string): "success" | "error" =>
  outcome === AUDIT_OUTCOME.SUCCESS ? "success" : "error";

type SearchParamValue = string | string[] | undefined;

export interface AuditLogFilters {
  category?: AuditActionCategory;
  actor?: string;
  outcome?: AuditOutcome;
  from?: string;
  to?: string;
  page: number;
}

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
const ACTOR_MAX_LENGTH = 254;

const first = (value: SearchParamValue): string =>
  (Array.isArray(value) ? value[0] : value)?.trim() ?? "";

const isCategory = (value: string): value is AuditActionCategory =>
  (Object.values(AUDIT_ACTION_CATEGORY) as string[]).includes(value);

const isOutcome = (value: string): value is AuditOutcome =>
  (Object.values(AUDIT_OUTCOME) as string[]).includes(value);

/** Page search params, validated; anything unexpected is dropped. */
export const parseAuditLogFilters = (
  searchParams: Record<string, SearchParamValue> = {},
): AuditLogFilters => {
  const category = first(searchParams.category);
  const actor = first(searchParams.actor).slice(0, ACTOR_MAX_LENGTH);
  const outcome = first(searchParams.outcome);
  const from = first(searchParams.from);
  const to = first(searchParams.to);
  const page = Number.parseInt(first(searchParams.page), 10);
  return {
    ...(isCategory(category) ? { category } : {}),
    ...(actor ? { actor } : {}),
    ...(isOutcome(outcome) ? { outcome } : {}),
    ...(ISO_DATE.test(from) ? { from } : {}),
    ...(ISO_DATE.test(to) ? { to } : {}),
    page: Number.isFinite(page) && page > 0 ? page : 1,
  };
};

/** JSON:API filter params shared by the list and the export. */
export const auditFilterParams = (
  filters: AuditLogFilters,
): Record<string, string> => {
  const params: Record<string, string> = {};
  if (filters.category) {
    params["filter[action__startswith]"] = `${filters.category}.`;
  }
  if (filters.actor) params["filter[actor]"] = filters.actor;
  if (filters.outcome) params["filter[outcome]"] = filters.outcome;
  if (filters.from) params["filter[inserted_at__gte]"] = filters.from;
  if (filters.to) params["filter[inserted_at__lte]"] = filters.to;
  return params;
};

export const auditListParams = (
  filters: AuditLogFilters,
): Record<string, string> => ({
  ...auditFilterParams(filters),
  sort: "-inserted_at",
  "page[size]": String(AUDIT_PAGE_SIZE),
  "page[number]": String(filters.page),
});

/** Same-origin CSV export link carrying the active filters. */
export const auditExportHref = (filters: AuditLogFilters): string => {
  const query = new URLSearchParams({
    ...auditFilterParams(filters),
    format: "csv",
  });
  return `${AUDIT_LOG_EXPORT_API}?${query.toString()}`;
};

/** Audit log page link with the given filters and page. */
export const auditPageHref = (filters: AuditLogFilters, page: number): string => {
  const query = new URLSearchParams();
  if (filters.category) query.set("category", filters.category);
  if (filters.actor) query.set("actor", filters.actor);
  if (filters.outcome) query.set("outcome", filters.outcome);
  if (filters.from) query.set("from", filters.from);
  if (filters.to) query.set("to", filters.to);
  if (page > 1) query.set("page", String(page));
  const serialized = query.toString();
  return serialized
    ? `${PRODUCT_ROUTE.AUDIT_LOG}?${serialized}`
    : PRODUCT_ROUTE.AUDIT_LOG;
};

/** Query params the export proxy forwards; everything else is dropped. */
export const AUDIT_EXPORT_FORWARDED_PARAMS = [
  "format",
  "filter[action]",
  "filter[action__startswith]",
  "filter[actor]",
  "filter[outcome]",
  "filter[target_type]",
  "filter[inserted_at__gte]",
  "filter[inserted_at__lte]",
] as const;

export const auditExportUpstreamQuery = (incoming: URLSearchParams): string => {
  const query = new URLSearchParams();
  for (const key of AUDIT_EXPORT_FORWARDED_PARAMS) {
    const value = incoming.get(key);
    if (value) query.set(key, value.slice(0, 512));
  }
  if (!query.has("format")) query.set("format", "csv");
  return query.toString();
};

/** "2026-10-30T09:15:00Z" -> local "30 Oct 2026, 09:15:00"; bad input stays. */
export const formatAuditTime = (value: string): string => {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || "—";
  return date.toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  });
};

/** Short form of a UUID-like id for table cells. */
export const shortId = (value: string): string =>
  value.length > 12 ? `${value.slice(0, 8)}…` : value;
