import { describe, expect, it } from "vitest";

import {
  CUSTODIAN_RUN_STATUS,
  type CustodianPolicyResource,
  type CustodianRunResource,
} from "@/cloudsneeker/types/custodian";

import {
  buildCustodianDashboard,
  buildCustodianReportRows,
  buildCustodianTabHref,
  CUSTODIAN_TAB,
  formatDuration,
  getCustodianTab,
  runDurationMs,
} from "./custodian-dashboard";

const policy = (
  id: string,
  name: string,
  scheduleEnabled = false,
): CustodianPolicyResource => ({
  id,
  type: "cloudsneeker-custodian-policies",
  attributes: {
    name,
    description: "",
    policy_yaml: "policies: []",
    provider_id: "provider-1",
    provider_alias: "Prod",
    provider_uid: "111",
    provider_type: "aws",
    schedule_enabled: scheduleEnabled,
  },
});

const run = (
  id: string,
  policyId: string,
  status: string,
  resourceCount?: number,
  extras: Partial<CustodianRunResource["attributes"]> = {},
): CustodianRunResource => ({
  id,
  type: "cloudsneeker-custodian-runs",
  attributes: {
    policy_id: policyId,
    provider_id: "provider-1",
    status: status as CustodianRunResource["attributes"]["status"],
    mode: "dryrun",
    trigger: "manual",
    summary:
      resourceCount === undefined ? undefined : { resource_count: resourceCount },
    ...extras,
  },
});

describe("buildCustodianDashboard", () => {
  it("aggregates policy and run metrics for the dashboard cards", () => {
    const dashboard = buildCustodianDashboard({
      policies: [
        policy("p1", "unused-ebs", true),
        policy("p2", "public-s3", false),
      ],
      runs: [
        run("r1", "p1", CUSTODIAN_RUN_STATUS.COMPLETED, 12),
        run("r2", "p1", CUSTODIAN_RUN_STATUS.FAILED, 0, {
          error: "credentials expired",
        }),
        run("r3", "p2", CUSTODIAN_RUN_STATUS.RUNNING),
        run("r4", "p2", CUSTODIAN_RUN_STATUS.PENDING),
      ],
    });

    expect(dashboard).toMatchObject({
      policyCount: 2,
      scheduledPolicyCount: 1,
      runCount: 4,
      completedRunCount: 1,
      failedRunCount: 1,
      activeRunCount: 2,
      resourcesMatched: 12,
      resourceTrends: [],
      findingSuggestions: [],
    });
  });

  it("builds resource-match trends from completed runs", () => {
    const dashboard = buildCustodianDashboard({
      policies: [policy("p1", "unused-ebs")],
      runs: [
        run("r1", "p1", CUSTODIAN_RUN_STATUS.COMPLETED, 4, {
          inserted_at: "2026-03-02T00:00:00Z",
          summary: {
            resource_count: 4,
            delta: { new_count: 1, gone_count: 0 },
          },
        }),
      ],
    });

    expect(dashboard.resourceTrends).toStrictEqual([
      {
        runId: "r1",
        policyId: "p1",
        policyName: "unused-ebs",
        insertedAt: "2026-03-02T00:00:00Z",
        resourcesMatched: 4,
        deltaNew: 1,
        deltaGone: 0,
      },
    ]);
  });

  it("lists recent runs newest first and ranks policies by resources", () => {
    const dashboard = buildCustodianDashboard({
      policies: [policy("p1", "unused-ebs"), policy("p2", "public-s3")],
      runs: [
        run("r-old", "p1", CUSTODIAN_RUN_STATUS.COMPLETED, 2, {
          inserted_at: "2026-01-01T00:00:00Z",
        }),
        run("r-new", "p2", CUSTODIAN_RUN_STATUS.COMPLETED, 9, {
          inserted_at: "2026-02-01T00:00:00Z",
        }),
        run("r-mid", "p1", CUSTODIAN_RUN_STATUS.COMPLETED, 5, {
          inserted_at: "2026-01-15T00:00:00Z",
        }),
      ],
    });

    expect(dashboard.recentRuns.map((row) => row.runId)).toStrictEqual([
      "r-new",
      "r-mid",
      "r-old",
    ]);
    expect(dashboard.topPolicies).toStrictEqual([
      expect.objectContaining({
        policyId: "p2",
        policyName: "public-s3",
        resourcesMatched: 9,
        runCount: 1,
      }),
      expect.objectContaining({
        policyId: "p1",
        policyName: "unused-ebs",
        resourcesMatched: 7,
        runCount: 2,
      }),
    ]);
  });

  it("handles empty tenants", () => {
    expect(buildCustodianDashboard({ policies: [], runs: [] })).toMatchObject({
      policyCount: 0,
      scheduledPolicyCount: 0,
      runCount: 0,
      completedRunCount: 0,
      failedRunCount: 0,
      activeRunCount: 0,
      resourcesMatched: 0,
      recentRuns: [],
      topPolicies: [],
    });
  });
});

describe("buildCustodianReportRows", () => {
  it("joins runs to policy labels for the reports table", () => {
    const rows = buildCustodianReportRows({
      policies: [policy("p1", "unused-ebs")],
      runs: [
        run("r1", "p1", CUSTODIAN_RUN_STATUS.COMPLETED, 3, {
          started_at: "2026-03-01T10:00:00Z",
          finished_at: "2026-03-01T10:01:30Z",
          policy_name: "unused-ebs",
          provider_alias: "Prod",
        }),
        run("r2", "missing", CUSTODIAN_RUN_STATUS.FAILED, undefined, {
          error: "boom",
        }),
      ],
    });

    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({
      runId: "r1",
      policyId: "p1",
      policyName: "unused-ebs",
      providerLabel: "Prod",
      status: CUSTODIAN_RUN_STATUS.COMPLETED,
      resourcesMatched: 3,
      durationMs: 90_000,
    });
    expect(rows[1]).toMatchObject({
      runId: "r2",
      policyName: "Unknown policy",
      resourcesMatched: null,
      error: "boom",
    });
  });
});

describe("runDurationMs", () => {
  it("returns elapsed milliseconds when both timestamps exist", () => {
    expect(
      runDurationMs("2026-03-01T10:00:00Z", "2026-03-01T10:00:05Z"),
    ).toBe(5000);
  });

  it("returns null when a timestamp is missing", () => {
    expect(runDurationMs(null, "2026-03-01T10:00:05Z")).toBeNull();
    expect(runDurationMs("2026-03-01T10:00:00Z", undefined)).toBeNull();
  });
});

describe("getCustodianTab", () => {
  it("defaults to dashboard and accepts policies/reports", () => {
    expect(getCustodianTab(undefined)).toBe(CUSTODIAN_TAB.DASHBOARD);
    expect(getCustodianTab("policies")).toBe(CUSTODIAN_TAB.POLICIES);
    expect(getCustodianTab("reports")).toBe(CUSTODIAN_TAB.REPORTS);
    expect(getCustodianTab("bogus")).toBe(CUSTODIAN_TAB.DASHBOARD);
  });
});

describe("buildCustodianTabHref", () => {
  it("keeps dashboard on the bare route", () => {
    expect(buildCustodianTabHref(CUSTODIAN_TAB.DASHBOARD)).toBe("/custodian");
    expect(buildCustodianTabHref(CUSTODIAN_TAB.REPORTS)).toBe(
      "/custodian?tab=reports",
    );
  });
});

describe("formatDuration", () => {
  it("formats ms, seconds, and minutes", () => {
    expect(formatDuration(null)).toBe("—");
    expect(formatDuration(250)).toBe("250 ms");
    expect(formatDuration(30_000)).toBe("30s");
    expect(formatDuration(90_000)).toBe("1m 30s");
  });
});
