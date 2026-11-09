// Pure helpers shared by the three product dashboards (Overview, Application
// Security, Governance). Every number comes from an existing API response;
// these functions only add, rank and format what the APIs return.

import { latestCompletedRunByTarget } from "@/cloudsneeker/lib/app-security-dashboard";
import type { TrivyRunResource } from "@/cloudsneeker/types/trivy";
import {
  FINDING_TRIAGE_STATUS,
  type FindingTriageStatus,
} from "@/types/findings-triage";

/** Where an activity row came from; drives its label and icon. */
export const ACTIVITY_KIND = {
  CLOUD_SCAN: "cloud_scan",
  APP_SCAN: "app_scan",
  POLICY_RUN: "policy_run",
} as const;

export type ActivityKind = (typeof ACTIVITY_KIND)[keyof typeof ACTIVITY_KIND];

export const ACTIVITY_KIND_LABEL: Record<ActivityKind, string> = {
  cloud_scan: "Cloud scan",
  app_scan: "Application scan",
  policy_run: "Policy dry-run",
};

/** Run outcome, normalised across the three run types. */
export const ACTIVITY_STATE = {
  RUNNING: "running",
  COMPLETED: "completed",
  FAILED: "failed",
  QUEUED: "pending",
} as const;

export type ActivityState =
  (typeof ACTIVITY_STATE)[keyof typeof ACTIVITY_STATE];

export interface ActivityItem {
  id: string;
  kind: ActivityKind;
  title: string;
  state: ActivityState;
  /** ISO time the run was created. */
  at: string;
  href: string;
  /** Findings or matched resources the run reported, when it says. */
  count: number | null;
}

/** Maps a run status string from any engine to the shared states. */
export const toActivityState = (
  status: string | null | undefined,
): ActivityState => {
  switch ((status ?? "").toLowerCase()) {
    case "completed":
    case "succeeded":
    case "success":
      return ACTIVITY_STATE.COMPLETED;
    case "failed":
    case "error":
    case "cancelled":
      return ACTIVITY_STATE.FAILED;
    case "executing":
    case "running":
      return ACTIVITY_STATE.RUNNING;
    default:
      return ACTIVITY_STATE.QUEUED;
  }
};

const timeOf = (value: string | null | undefined): number => {
  const time = value ? Date.parse(value) : Number.NaN;
  return Number.isFinite(time) ? time : 0;
};

/** Newest first across every source, at most `limit` rows. */
export const mergeActivity = (
  groups: ActivityItem[][],
  limit: number,
): ActivityItem[] =>
  groups
    .flat()
    .filter((item) => item.at)
    .sort((left, right) => timeOf(right.at) - timeOf(left.at))
    .slice(0, limit);

/** Aggregate of the per-framework compliance rows (compliance watchlist API). */
export interface ComplianceFrameworkRow {
  id: string;
  label: string;
  passed: number;
  failed: number;
  manual: number;
  total: number;
  /** Passed share of all requirements, 0-100 (the watchlist adapter score). */
  score: number;
}

export interface ComplianceSummary {
  frameworkCount: number;
  passed: number;
  failed: number;
  manual: number;
  total: number;
  /** Passed / total requirements across every framework, or null when none. */
  percent: number | null;
}

export const summarizeCompliance = (
  rows: ComplianceFrameworkRow[],
): ComplianceSummary => {
  const totals = rows.reduce(
    (sum, row) => ({
      passed: sum.passed + row.passed,
      failed: sum.failed + row.failed,
      manual: sum.manual + row.manual,
      total: sum.total + row.total,
    }),
    { passed: 0, failed: 0, manual: 0, total: 0 },
  );
  // Same formula as each framework's score (compliance watchlist adapter):
  // passed over all requirements, so manual ones count as not passed.
  return {
    frameworkCount: rows.length,
    ...totals,
    percent:
      totals.total > 0
        ? Math.round((totals.passed / totals.total) * 100)
        : null,
  };
};

/** Frameworks with the most failed requirements first, then the lowest score. */
export const rankFrameworksByGap = (
  rows: ComplianceFrameworkRow[],
): ComplianceFrameworkRow[] =>
  [...rows].sort(
    (left, right) =>
      right.failed - left.failed ||
      left.score - right.score ||
      left.label.localeCompare(right.label),
  );

/** Triage states shown as remediation progress, in workflow order. */
export const REMEDIATION_STATUS_ORDER = [
  FINDING_TRIAGE_STATUS.OPEN,
  FINDING_TRIAGE_STATUS.UNDER_REVIEW,
  FINDING_TRIAGE_STATUS.REMEDIATING,
  FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
  FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
  FINDING_TRIAGE_STATUS.RESOLVED,
] as const satisfies readonly FindingTriageStatus[];

export const REMEDIATION_STATUS_LABEL: Record<FindingTriageStatus, string> = {
  open: "Open",
  under_review: "Under review",
  remediating: "Remediating",
  resolved: "Resolved",
  risk_accepted: "Risk accepted",
  false_positive: "False positive",
  reopened: "Reopened",
};

export interface RemediationProgress {
  counts: { status: FindingTriageStatus; count: number }[];
  total: number;
  /** Findings someone has acted on (not open), 0-100, or null when none. */
  handledPercent: number | null;
}

/** `null` counts (failed requests) make the whole block unknown. */
export const buildRemediationProgress = (
  counts: Partial<Record<FindingTriageStatus, number | null>>,
): RemediationProgress | null => {
  const rows = REMEDIATION_STATUS_ORDER.map((status) => ({
    status,
    count: counts[status],
  }));
  if (rows.some((row) => row.count === null || row.count === undefined)) {
    return null;
  }
  const resolved = rows as { status: FindingTriageStatus; count: number }[];
  const total = resolved.reduce((sum, row) => sum + row.count, 0);
  const open =
    resolved.find((row) => row.status === FINDING_TRIAGE_STATUS.OPEN)?.count ??
    0;
  return {
    counts: resolved,
    total,
    handledPercent:
      total > 0 ? Math.round(((total - open) / total) * 100) : null,
  };
};

export interface RankedTarget {
  targetId: string;
  name: string;
  mode: string;
  findings: number;
  runId: string;
  scanId: string | null;
  at: string | null;
}

/**
 * Targets by findings in their latest completed scan, most first. `runs` is
 * newest first (as the dashboards request it); runs of deleted targets are
 * left out when `targetIds` is given.
 */
export const rankTargetsByFindings = (
  runs: TrivyRunResource[],
  targetIds?: ReadonlySet<string>,
): RankedTarget[] =>
  Array.from(latestCompletedRunByTarget(runs).values())
    .filter((run) => !targetIds || targetIds.has(run.attributes.target_id))
    .map((run) => ({
      targetId: run.attributes.target_id,
      name: run.attributes.target_name || run.attributes.target_id,
      mode: run.attributes.target_mode ?? "",
      findings: Number(run.attributes.summary?.finding_count ?? 0) || 0,
      runId: run.id,
      scanId: run.attributes.scan_id ?? run.attributes.summary?.scan_id ?? null,
      at: run.attributes.inserted_at ?? null,
    }))
    .sort(
      (left, right) =>
        right.findings - left.findings || left.name.localeCompare(right.name),
    );

export interface TrendPoint {
  /** `YYYY-MM-DD` (UTC). */
  day: string;
  value: number;
}

const dayOf = (value: string | null | undefined): string | null => {
  const time = timeOf(value);
  return time > 0 ? new Date(time).toISOString().slice(0, 10) : null;
};

/**
 * Sums `valueOf` per UTC day for the `days` days ending at `now`. Days
 * without data are 0, so the bars keep a steady time axis.
 */
export const dailyTrend = <T>(
  items: T[],
  dateOf: (item: T) => string | null | undefined,
  valueOf: (item: T) => number,
  days: number,
  now: Date = new Date(),
): TrendPoint[] => {
  const totals = new Map<string, number>();
  for (const item of items) {
    const day = dayOf(dateOf(item));
    if (!day) continue;
    totals.set(day, (totals.get(day) ?? 0) + valueOf(item));
  }
  const end = Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate(),
  );
  return Array.from({ length: days }, (_, index) => {
    const day = new Date(end - (days - 1 - index) * 86_400_000)
      .toISOString()
      .slice(0, 10);
    return { day, value: totals.get(day) ?? 0 };
  });
};

/** Findings reported per day by completed application scans. */
export const appScanFindingTrend = (
  runs: TrivyRunResource[],
  days: number,
  now?: Date,
): TrendPoint[] =>
  dailyTrend(
    runs.filter(
      (run) =>
        toActivityState(run.attributes.status) === ACTIVITY_STATE.COMPLETED,
    ),
    (run) => run.attributes.inserted_at,
    (run) => Number(run.attributes.summary?.finding_count ?? 0) || 0,
    days,
    now,
  );

/** Share of `part` in `whole` as a whole percent, or null. */
export const percentOf = (part: number, whole: number): number | null =>
  whole > 0 ? Math.round((part / whole) * 100) : null;
