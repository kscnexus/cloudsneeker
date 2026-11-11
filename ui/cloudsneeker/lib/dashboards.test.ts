import { describe, expect, it } from "vitest";

import type { TrivyRunResource } from "@/cloudsneeker/types/trivy";

import {
  ACTIVITY_KIND,
  ACTIVITY_STATE,
  type ActivityItem,
  appScanFindingTrend,
  buildRemediationProgress,
  type ComplianceFrameworkRow,
  dailyTrend,
  mergeActivity,
  percentOf,
  rankFrameworksByGap,
  rankTargetsByFindings,
  summarizeCompliance,
  toActivityState,
} from "./dashboards";

const run = (
  id: string,
  targetId: string,
  status: string,
  insertedAt: string,
  findings?: number,
): TrivyRunResource =>
  ({
    id,
    type: "trivy-runs",
    attributes: {
      target_id: targetId,
      target_name: `Target ${targetId}`,
      target_mode: "repo",
      provider_id: "p",
      status,
      trigger: "manual",
      inserted_at: insertedAt,
      summary: findings === undefined ? {} : { finding_count: findings },
    },
  }) as TrivyRunResource;

const framework = (
  id: string,
  passed: number,
  failed: number,
  manual: number,
): ComplianceFrameworkRow => {
  const total = passed + failed + manual;
  return {
    id,
    label: id.toUpperCase(),
    passed,
    failed,
    manual,
    total,
    score: total > 0 ? Math.round((passed / total) * 100) : 0,
  };
};

describe("toActivityState", () => {
  it("normalises run and scan states", () => {
    expect(toActivityState("completed")).toBe(ACTIVITY_STATE.COMPLETED);
    expect(toActivityState("executing")).toBe(ACTIVITY_STATE.RUNNING);
    expect(toActivityState("running")).toBe(ACTIVITY_STATE.RUNNING);
    expect(toActivityState("failed")).toBe(ACTIVITY_STATE.FAILED);
    expect(toActivityState("cancelled")).toBe(ACTIVITY_STATE.FAILED);
    expect(toActivityState("available")).toBe(ACTIVITY_STATE.QUEUED);
    expect(toActivityState(undefined)).toBe(ACTIVITY_STATE.QUEUED);
  });
});

describe("mergeActivity", () => {
  const item = (id: string, at: string): ActivityItem => ({
    id,
    kind: ACTIVITY_KIND.CLOUD_SCAN,
    title: id,
    state: ACTIVITY_STATE.COMPLETED,
    at,
    href: "/",
    count: null,
  });

  it("sorts every source newest first and keeps the limit", () => {
    const merged = mergeActivity(
      [
        [item("a", "2026-11-01T00:00:00Z"), item("b", "2026-11-05T00:00:00Z")],
        [item("c", "2026-11-03T00:00:00Z"), item("d", "")],
      ],
      2,
    );
    expect(merged.map((entry) => entry.id)).toEqual(["b", "c"]);
  });
});

describe("summarizeCompliance", () => {
  it("uses passed over all requirements, like each framework score", () => {
    const summary = summarizeCompliance([
      framework("cis", 60, 30, 10),
      framework("iso", 20, 10, 70),
    ]);
    expect(summary).toEqual({
      frameworkCount: 2,
      passed: 80,
      failed: 40,
      manual: 80,
      total: 200,
      percent: 40,
    });
  });

  it("has no percent without requirements", () => {
    expect(summarizeCompliance([]).percent).toBeNull();
  });
});

describe("rankFrameworksByGap", () => {
  it("puts the most failed requirements first, then the lowest score", () => {
    const ranked = rankFrameworksByGap([
      framework("a", 90, 5, 0),
      framework("b", 10, 20, 0),
      framework("c", 50, 20, 0),
    ]);
    expect(ranked.map((row) => row.id)).toEqual(["b", "c", "a"]);
  });
});

describe("buildRemediationProgress", () => {
  it("counts every state and the triaged share", () => {
    const progress = buildRemediationProgress({
      open: 6,
      under_review: 1,
      remediating: 1,
      risk_accepted: 1,
      false_positive: 0,
      resolved: 1,
    });
    expect(progress?.total).toBe(10);
    expect(progress?.handledPercent).toBe(40);
    expect(progress?.counts.map((row) => row.status)).toEqual([
      "open",
      "under_review",
      "remediating",
      "risk_accepted",
      "false_positive",
      "resolved",
    ]);
  });

  it("is unknown when any count failed to load", () => {
    expect(
      buildRemediationProgress({
        open: 1,
        under_review: null,
        remediating: 0,
        risk_accepted: 0,
        false_positive: 0,
        resolved: 0,
      }),
    ).toBeNull();
  });
});

describe("rankTargetsByFindings", () => {
  it("ranks targets by their latest completed scan only", () => {
    const runs = [
      run("r4", "t1", "failed", "2026-11-04T00:00:00Z"),
      run("r3", "t1", "completed", "2026-11-03T00:00:00Z", 2),
      run("r2", "t2", "completed", "2026-11-02T00:00:00Z", 9),
      run("r1", "t1", "completed", "2026-11-01T00:00:00Z", 50),
    ];
    const ranked = rankTargetsByFindings(runs);
    expect(ranked.map((target) => [target.targetId, target.findings])).toEqual([
      ["t2", 9],
      ["t1", 2],
    ]);
  });

  it("leaves out deleted targets", () => {
    const runs = [run("r1", "gone", "completed", "2026-11-01T00:00:00Z", 3)];
    expect(rankTargetsByFindings(runs, new Set(["t1"]))).toEqual([]);
  });
});

describe("dailyTrend", () => {
  const now = new Date("2026-11-09T12:00:00Z");

  it("keeps a fixed axis and sums per day", () => {
    const points = dailyTrend(
      [
        { at: "2026-11-09T01:00:00Z", value: 2 },
        { at: "2026-11-09T05:00:00Z", value: 3 },
        { at: "2026-11-07T05:00:00Z", value: 1 },
        { at: "2026-10-01T05:00:00Z", value: 99 },
      ],
      (item) => item.at,
      (item) => item.value,
      3,
      now,
    );
    expect(points).toEqual([
      { day: "2026-11-07", value: 1 },
      { day: "2026-11-08", value: 0 },
      { day: "2026-11-09", value: 5 },
    ]);
  });

  it("counts completed application scans only", () => {
    const points = appScanFindingTrend(
      [
        run("r1", "t1", "completed", "2026-11-09T01:00:00Z", 4),
        run("r2", "t1", "failed", "2026-11-09T02:00:00Z", 7),
      ],
      1,
      now,
    );
    expect(points).toEqual([{ day: "2026-11-09", value: 4 }]);
  });
});

describe("percentOf", () => {
  it("rounds and guards against zero", () => {
    expect(percentOf(1, 3)).toBe(33);
    expect(percentOf(1, 0)).toBeNull();
  });
});
