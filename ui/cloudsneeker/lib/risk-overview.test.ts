import { describe, expect, it } from "vitest";

import { EXECUTIVE_REPORT_FIXTURE } from "@/cloudsneeker/components/report-view.fixture";
import {
  REPORT_RESOURCE_TYPE,
  REPORT_RUN_STATUS,
  type ReportRunResource,
  type ReportRunStatus,
} from "@/cloudsneeker/types/reports";

import {
  buildDomainSummaries,
  buildRiskOverview,
  buildSeverityTotals,
  buildTopRisks,
  buildTrendBars,
  hasNewerActiveRun,
  latestCompletedRun,
  reportPayloadFrom,
  RISK_DOMAIN_ORDER,
} from "./risk-overview";

const run = (id: string, status: ReportRunStatus): ReportRunResource => ({
  type: REPORT_RESOURCE_TYPE.REPORT_RUNS,
  id,
  attributes: {
    inserted_at: "2026-10-28T09:00:00Z",
    report_type: "executive",
    report_name: "Executive summary",
    params: {},
    formats: ["pdf"],
    available_formats: ["pdf", "json"],
    status,
    trigger: "manual",
    error: "",
    started_at: null,
    finished_at: null,
  },
});

describe("latestCompletedRun / hasNewerActiveRun", () => {
  it("picks the newest completed run and flags a newer active one", () => {
    const runs = [
      run("new", REPORT_RUN_STATUS.RUNNING),
      run("done", REPORT_RUN_STATUS.COMPLETED),
      run("old", REPORT_RUN_STATUS.COMPLETED),
    ];

    const latest = latestCompletedRun(runs);

    expect(latest?.id).toBe("done");
    expect(hasNewerActiveRun(runs, latest)).toBe(true);
  });

  it("ignores active runs older than the latest completed one", () => {
    const runs = [
      run("done", REPORT_RUN_STATUS.COMPLETED),
      run("stuck", REPORT_RUN_STATUS.PENDING),
    ];

    expect(hasNewerActiveRun(runs, latestCompletedRun(runs))).toBe(false);
  });

  it("returns null without completed runs", () => {
    expect(latestCompletedRun([run("x", REPORT_RUN_STATUS.FAILED)])).toBeNull();
  });
});

describe("reportPayloadFrom", () => {
  it("reads data.attributes and rejects errors and lists", () => {
    expect(
      reportPayloadFrom({ data: { attributes: EXECUTIVE_REPORT_FIXTURE } }),
    ).toBe(EXECUTIVE_REPORT_FIXTURE);
    expect(reportPayloadFrom({ error: "Not found" })).toBeNull();
    expect(reportPayloadFrom({ data: [] })).toBeNull();
    expect(reportPayloadFrom(undefined)).toBeNull();
  });
});

describe("buildDomainSummaries", () => {
  it("returns every area in order, marking areas without data", () => {
    const domains = buildDomainSummaries(EXECUTIVE_REPORT_FIXTURE.sources);

    expect(domains.map((item) => item.domain)).toEqual([...RISK_DOMAIN_ORDER]);
    expect(domains[0]).toMatchObject({
      domain: "cloud",
      score: 70,
      grade: "C",
      openIssues: 30,
      critical: 4,
      coverage: "2 account(s)",
      hasData: true,
    });
    expect(domains[0].href).toContain("/findings?");
    expect(domains[1]).toMatchObject({
      domain: "application",
      label: "Application Security",
      hasData: false,
      grade: "—",
      href: "/application-security",
    });
    expect(domains[3].href).toBe("/governance");
  });
});

describe("buildSeverityTotals", () => {
  it("lists every severity with an open findings link", () => {
    const totals = buildSeverityTotals({ critical: 5, high: 37 });

    expect(totals.map((item) => [item.severity, item.count])).toEqual([
      ["critical", 5],
      ["high", 37],
      ["medium", 0],
      ["low", 0],
      ["informational", 0],
    ]);
    const params = new URLSearchParams(totals[0].href.split("?")[1]);
    expect(params.get("filter[severity__in]")).toBe("critical");
    expect(params.get("filter[status__in]")).toBe("FAIL");
    expect(params.get("filter[muted]")).toBe("false");
  });
});

describe("buildTopRisks", () => {
  it("links each risk to its failed findings and caps the list", () => {
    const risks = buildTopRisks(EXECUTIVE_REPORT_FIXTURE.top_risks, 1);

    expect(risks).toHaveLength(1);
    expect(risks[0]).toMatchObject({
      checkId: "s3_bucket_public_access",
      title: "S3 bucket allows public access",
      severity: "critical",
      resources: 4,
    });
    expect(
      new URLSearchParams(risks[0].href.split("?")[1]).get(
        "filter[check_id__in]",
      ),
    ).toBe("s3_bucket_public_access");
  });

  it("falls back to the check id when a title is missing", () => {
    expect(
      buildTopRisks([{ check_id: "iam_root_mfa", severity: "high" }])[0].title,
    ).toBe("iam_root_mfa");
  });
});

describe("buildTrendBars", () => {
  it("scales bars to the busiest point and splits out critical", () => {
    const bars = buildTrendBars([
      { date: "2026-10-01", fail: 50, pass: 0, critical: 10, high: 0 },
      { date: "2026-10-02", fail: 25, pass: 0, critical: 0, high: 0 },
    ]);

    expect(bars[0]).toMatchObject({ heightPct: 100, criticalPct: 20 });
    expect(bars[1]).toMatchObject({ heightPct: 50, criticalPct: 0 });
  });

  it("keeps a visible stub when every point is zero", () => {
    expect(
      buildTrendBars([
        { date: "2026-10-01", fail: 0, pass: 1, critical: 0, high: 0 },
      ])[0].heightPct,
    ).toBe(4);
  });
});

describe("buildRiskOverview", () => {
  it("maps the executive payload into the risk view", () => {
    const model = buildRiskOverview(EXECUTIVE_REPORT_FIXTURE, "run-1");

    expect(model).toMatchObject({
      runId: "run-1",
      reportHref: "/reports/run-1",
      score: 72.4,
      grade: "C",
      openIssues: 42,
      trendDelta: -8,
      isEmpty: false,
    });
    expect(model.domains).toHaveLength(4);
    expect(model.topRisks).toHaveLength(1);
    expect(model.severityTotals[1].count).toBe(37);
  });
});
