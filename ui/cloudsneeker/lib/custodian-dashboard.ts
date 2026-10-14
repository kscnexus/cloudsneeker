import {
  CUSTODIAN_RUN_STATUS,
  type CustodianPolicyResource,
  type CustodianRunResource,
  type CustodianRunStatus,
} from "@/cloudsneeker/types/custodian";

export const CUSTODIAN_TAB = {
  DASHBOARD: "dashboard",
  POLICIES: "policies",
  REPORTS: "reports",
} as const;

export type CustodianTab = (typeof CUSTODIAN_TAB)[keyof typeof CUSTODIAN_TAB];

export interface CustodianDashboardRecentRun {
  runId: string;
  policyId: string;
  policyName: string;
  status: CustodianRunStatus;
  trigger: string;
  resourcesMatched: number | null;
  insertedAt: string | null;
  error: string;
}

export interface CustodianDashboardTopPolicy {
  policyId: string;
  policyName: string;
  runCount: number;
  resourcesMatched: number;
  providerLabel: string;
}

export interface CustodianDashboardMetrics {
  policyCount: number;
  scheduledPolicyCount: number;
  runCount: number;
  completedRunCount: number;
  failedRunCount: number;
  activeRunCount: number;
  resourcesMatched: number;
  recentRuns: CustodianDashboardRecentRun[];
  topPolicies: CustodianDashboardTopPolicy[];
}

export interface CustodianReportRow {
  runId: string;
  policyId: string;
  policyName: string;
  providerLabel: string;
  status: CustodianRunStatus;
  trigger: string;
  resourcesMatched: number | null;
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  error: string;
  insertedAt: string | null;
}

interface CustodianDashboardInput {
  policies: CustodianPolicyResource[];
  runs: CustodianRunResource[];
  recentLimit?: number;
  topLimit?: number;
}

const ACTIVE_STATUSES = new Set<CustodianRunStatus>([
  CUSTODIAN_RUN_STATUS.PENDING,
  CUSTODIAN_RUN_STATUS.RUNNING,
]);

const policyNameById = (
  policies: CustodianPolicyResource[],
): Map<string, string> =>
  new Map(policies.map((policy) => [policy.id, policy.attributes.name]));

const providerLabelFor = (
  policy: CustodianPolicyResource | undefined,
  run: CustodianRunResource,
): string =>
  run.attributes.provider_alias ||
  policy?.attributes.provider_alias ||
  run.attributes.provider_uid ||
  policy?.attributes.provider_uid ||
  run.attributes.provider_id ||
  policy?.attributes.provider_id ||
  "—";

export function runDurationMs(
  startedAt: string | null | undefined,
  finishedAt: string | null | undefined,
): number | null {
  if (!startedAt || !finishedAt) return null;
  const start = Date.parse(startedAt);
  const end = Date.parse(finishedAt);
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) return null;
  return end - start;
}

export function buildCustodianDashboard({
  policies,
  runs,
  recentLimit = 8,
  topLimit = 5,
}: CustodianDashboardInput): CustodianDashboardMetrics {
  const names = policyNameById(policies);
  const policyById = new Map(policies.map((policy) => [policy.id, policy]));

  let completedRunCount = 0;
  let failedRunCount = 0;
  let activeRunCount = 0;
  let resourcesMatched = 0;

  const resourcesByPolicy = new Map<string, number>();
  const runsByPolicy = new Map<string, number>();

  for (const run of runs) {
    const status = run.attributes.status;
    if (status === CUSTODIAN_RUN_STATUS.COMPLETED) completedRunCount += 1;
    else if (status === CUSTODIAN_RUN_STATUS.FAILED) failedRunCount += 1;
    else if (ACTIVE_STATUSES.has(status)) activeRunCount += 1;

    const count = run.attributes.summary?.resource_count;
    if (typeof count === "number" && status === CUSTODIAN_RUN_STATUS.COMPLETED) {
      resourcesMatched += count;
      resourcesByPolicy.set(
        run.attributes.policy_id,
        (resourcesByPolicy.get(run.attributes.policy_id) ?? 0) + count,
      );
    }
    runsByPolicy.set(
      run.attributes.policy_id,
      (runsByPolicy.get(run.attributes.policy_id) ?? 0) + 1,
    );
  }

  const recentRuns = [...runs]
    .sort((left, right) => {
      const leftAt = left.attributes.inserted_at ?? "";
      const rightAt = right.attributes.inserted_at ?? "";
      return rightAt.localeCompare(leftAt);
    })
    .slice(0, recentLimit)
    .map((run) => ({
      runId: run.id,
      policyId: run.attributes.policy_id,
      policyName:
        run.attributes.policy_name ||
        names.get(run.attributes.policy_id) ||
        "Unknown policy",
      status: run.attributes.status,
      trigger: String(run.attributes.trigger ?? "manual"),
      resourcesMatched:
        typeof run.attributes.summary?.resource_count === "number"
          ? run.attributes.summary.resource_count
          : null,
      insertedAt: run.attributes.inserted_at ?? null,
      error: run.attributes.error ?? "",
    }));

  const topPolicies = Array.from(runsByPolicy.keys())
    .map((policyId) => {
      const policy = policyById.get(policyId);
      return {
        policyId,
        policyName: names.get(policyId) || policy?.attributes.name || "Unknown policy",
        runCount: runsByPolicy.get(policyId) ?? 0,
        resourcesMatched: resourcesByPolicy.get(policyId) ?? 0,
        providerLabel: providerLabelFor(policy, {
          id: "",
          type: "cloudsneeker-custodian-runs",
          attributes: {
            policy_id: policyId,
            provider_id: policy?.attributes.provider_id ?? "",
            status: CUSTODIAN_RUN_STATUS.COMPLETED,
            mode: "dryrun",
            provider_alias: policy?.attributes.provider_alias,
            provider_uid: policy?.attributes.provider_uid,
          },
        }),
      };
    })
    .sort((left, right) => {
      if (right.resourcesMatched !== left.resourcesMatched) {
        return right.resourcesMatched - left.resourcesMatched;
      }
      return right.runCount - left.runCount;
    })
    .slice(0, topLimit);

  return {
    policyCount: policies.length,
    scheduledPolicyCount: policies.filter(
      (policy) => policy.attributes.schedule_enabled,
    ).length,
    runCount: runs.length,
    completedRunCount,
    failedRunCount,
    activeRunCount,
    resourcesMatched,
    recentRuns,
    topPolicies,
  };
}

export function buildCustodianReportRows({
  policies,
  runs,
}: {
  policies: CustodianPolicyResource[];
  runs: CustodianRunResource[];
}): CustodianReportRow[] {
  const names = policyNameById(policies);
  const policyById = new Map(policies.map((policy) => [policy.id, policy]));

  return [...runs]
    .sort((left, right) => {
      const leftAt = left.attributes.inserted_at ?? "";
      const rightAt = right.attributes.inserted_at ?? "";
      return rightAt.localeCompare(leftAt);
    })
    .map((run) => {
      const policy = policyById.get(run.attributes.policy_id);
      return {
        runId: run.id,
        policyId: run.attributes.policy_id,
        policyName:
          run.attributes.policy_name ||
          names.get(run.attributes.policy_id) ||
          "Unknown policy",
        providerLabel: providerLabelFor(policy, run),
        status: run.attributes.status,
        trigger: String(run.attributes.trigger ?? "manual"),
        resourcesMatched:
          typeof run.attributes.summary?.resource_count === "number"
            ? run.attributes.summary.resource_count
            : null,
        startedAt: run.attributes.started_at ?? null,
        finishedAt: run.attributes.finished_at ?? null,
        durationMs: runDurationMs(
          run.attributes.started_at,
          run.attributes.finished_at,
        ),
        error: run.attributes.error ?? "",
        insertedAt: run.attributes.inserted_at ?? null,
      };
    });
}

export function getCustodianTab(
  value: string | string[] | undefined,
): CustodianTab {
  if (typeof value === "string") {
    if (value === CUSTODIAN_TAB.POLICIES) return CUSTODIAN_TAB.POLICIES;
    if (value === CUSTODIAN_TAB.REPORTS) return CUSTODIAN_TAB.REPORTS;
  }
  return CUSTODIAN_TAB.DASHBOARD;
}

export function buildCustodianTabHref(tab: CustodianTab): string {
  if (tab === CUSTODIAN_TAB.DASHBOARD) return "/custodian";
  return `/custodian?tab=${tab}`;
}

export function formatDuration(durationMs: number | null): string {
  if (durationMs === null) return "—";
  if (durationMs < 1000) return `${durationMs} ms`;
  const seconds = Math.round(durationMs / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return remainder === 0 ? `${minutes}m` : `${minutes}m ${remainder}s`;
}
