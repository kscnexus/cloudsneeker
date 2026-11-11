// Alert history: each firing of an alert rule (`GET /alerts/events`), its
// status, and the actions that move it. The API keeps who changed the status
// and when; the UI reads them back.

import {
  FINDING_AREA,
  type FindingArea,
} from "@/cloudsneeker/types/area-findings";

import { alertAreaLabel, isFindingArea } from "./alert-areas";
import { LIST_PAGE_SIZE, type ListFilters } from "./list-filters";

export const ALERTS_TAB_PARAM = "tab";
export const ALERTS_HISTORY_TAB = "history";

export const ALERT_EVENT_STATUS = {
  OPEN: "open",
  ACKNOWLEDGED: "acknowledged",
  RESOLVED: "resolved",
  DISMISSED: "dismissed",
} as const;

export type AlertEventStatus =
  (typeof ALERT_EVENT_STATUS)[keyof typeof ALERT_EVENT_STATUS];

export const ALERT_EVENT_STATUS_OPTIONS: readonly {
  value: AlertEventStatus;
  label: string;
}[] = [
  { value: ALERT_EVENT_STATUS.OPEN, label: "Open" },
  { value: ALERT_EVENT_STATUS.ACKNOWLEDGED, label: "Acknowledged" },
  { value: ALERT_EVENT_STATUS.RESOLVED, label: "Resolved" },
  { value: ALERT_EVENT_STATUS.DISMISSED, label: "Dismissed" },
];

const STATUS_VALUES = new Set<string>(Object.values(ALERT_EVENT_STATUS));

export const isAlertEventStatus = (value: unknown): value is AlertEventStatus =>
  typeof value === "string" && STATUS_VALUES.has(value);

export const alertEventStatusLabel = (status: AlertEventStatus): string =>
  ALERT_EVENT_STATUS_OPTIONS.find((option) => option.value === status)?.label ??
  status;

export interface AlertEventTransition {
  status: AlertEventStatus;
  label: string;
}

/** Actions offered for an event in a given status. */
export const alertEventTransitions = (
  status: AlertEventStatus,
): AlertEventTransition[] => {
  const acknowledge = {
    status: ALERT_EVENT_STATUS.ACKNOWLEDGED,
    label: "Acknowledge",
  };
  const resolve = { status: ALERT_EVENT_STATUS.RESOLVED, label: "Resolve" };
  const dismiss = { status: ALERT_EVENT_STATUS.DISMISSED, label: "Dismiss" };
  const reopen = { status: ALERT_EVENT_STATUS.OPEN, label: "Reopen" };
  switch (status) {
    case ALERT_EVENT_STATUS.OPEN:
      return [acknowledge, resolve, dismiss];
    case ALERT_EVENT_STATUS.ACKNOWLEDGED:
      return [resolve, dismiss, reopen];
    default:
      return [reopen];
  }
};

/** Query for `GET /alerts/events`: Status and Module selects, search, page. */
export const alertHistoryQuery = (
  filters: ListFilters,
): Record<string, string> => ({
  "page[size]": String(LIST_PAGE_SIZE),
  "page[number]": String(filters.page),
  sort: "-inserted_at",
  ...(filters.search ? { "filter[search]": filters.search } : {}),
  ...(isAlertEventStatus(filters.status)
    ? { "filter[status]": filters.status }
    : {}),
  ...(isFindingArea(filters.type) ? { "filter[area]": filters.type } : {}),
});

export interface AlertEventAreaCount {
  area: FindingArea;
  label: string;
  count: number;
}

export interface AlertEventChange {
  at: string | null;
  by: string | null;
}

export interface AlertEventItem {
  id: string;
  ruleId: string | null;
  ruleName: string;
  trigger: string;
  insertedAt: string;
  total: number;
  areas: AlertEventAreaCount[];
  severityCounts: Record<string, number>;
  links: string[];
  delivered: boolean;
  status: AlertEventStatus;
  statusChange: AlertEventChange;
  note: string;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"];

/** "critical 1 · high 4", most severe first. */
export const severitySummary = (counts: Record<string, number>): string =>
  [
    ...SEVERITY_ORDER.filter((severity) => counts[severity]),
    ...Object.keys(counts).filter(
      (severity) => !SEVERITY_ORDER.includes(severity) && counts[severity],
    ),
  ]
    .map((severity) => `${severity} ${counts[severity]}`)
    .join(" · ");

const AREA_ORDER: FindingArea[] = [
  FINDING_AREA.CLOUD,
  FINDING_AREA.APPLICATION_SECURITY,
  FINDING_AREA.GOVERNANCE,
];

const asRecord = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" ? (value as Record<string, unknown>) : {};

const asCounts = (value: unknown): Record<string, number> =>
  Object.fromEntries(
    Object.entries(asRecord(value)).filter(
      (entry): entry is [string, number] =>
        typeof entry[1] === "number" && entry[1] > 0,
    ),
  );

/** JSON:API rows of `/alerts/events` as flat items; malformed rows dropped. */
export const toAlertEvents = (response: unknown): AlertEventItem[] => {
  const rows = asRecord(response).data;
  if (!Array.isArray(rows)) return [];
  return rows.flatMap((row) => {
    const { id } = asRecord(row);
    const attributes = asRecord(asRecord(row).attributes);
    if (typeof id !== "string") return [];
    const areaCounts = asCounts(attributes.area_counts);
    const changedBy = asRecord(attributes.status_changed_by);
    const status = isAlertEventStatus(attributes.status)
      ? attributes.status
      : ALERT_EVENT_STATUS.OPEN;
    return [
      {
        id,
        ruleId:
          typeof attributes.rule_id === "string" ? attributes.rule_id : null,
        ruleName: String(attributes.rule_name ?? ""),
        trigger: String(attributes.trigger ?? ""),
        insertedAt: String(attributes.inserted_at ?? ""),
        total: typeof attributes.total === "number" ? attributes.total : 0,
        areas: AREA_ORDER.filter((area) => areaCounts[area]).map((area) => ({
          area,
          label: alertAreaLabel(area),
          count: areaCounts[area],
        })),
        severityCounts: asCounts(attributes.severity_counts),
        links: Array.isArray(attributes.links)
          ? attributes.links.filter(
              (link): link is string => typeof link === "string",
            )
          : [],
        delivered: attributes.delivered === true,
        status,
        statusChange: {
          at:
            typeof attributes.status_changed_at === "string"
              ? attributes.status_changed_at
              : null,
          by: typeof changedBy.name === "string" ? changedBy.name : null,
        },
        note: typeof attributes.note === "string" ? attributes.note : "",
      },
    ];
  });
};

/** Label for a stored link: which page it opens. */
export const alertLinkLabel = (link: string): string => {
  if (link.includes("/application-security/"))
    return "Application Security run";
  if (link.includes("/governance/")) return "Governance run";
  return "Findings";
};
