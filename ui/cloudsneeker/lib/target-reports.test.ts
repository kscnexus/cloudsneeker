import { describe, expect, it } from "vitest";

import {
  TRIVY_MODE,
  type TrivyMode,
  type TrivyTargetResource,
} from "@/cloudsneeker/types/trivy";

import {
  describeReportProgress,
  isFinishedReportStatus,
  reportTypeForTargetMode,
  repositoryReportJobs,
  runWithConcurrency,
} from "./target-reports";

const target = (
  id: string,
  name: string,
  mode: TrivyMode,
): TrivyTargetResource => ({
  id,
  type: "cloudsneeker-trivy-targets",
  attributes: { name, description: "", mode, config: {}, provider_id: "p" },
});

describe("reportTypeForTargetMode", () => {
  it("maps SAST targets to the SAST report and dependency scans to SCA", () => {
    expect(reportTypeForTargetMode(TRIVY_MODE.SAST)).toBe("sast");
    expect(reportTypeForTargetMode(TRIVY_MODE.REPO)).toBe("sca");
    expect(reportTypeForTargetMode(TRIVY_MODE.IMAGE)).toBe("sca");
    expect(reportTypeForTargetMode(TRIVY_MODE.SBOM)).toBe("sca");
  });

  it("has no per-target report for IaC targets", () => {
    expect(reportTypeForTargetMode(TRIVY_MODE.IAC)).toBeNull();
  });
});

describe("repositoryReportJobs", () => {
  it("keeps repository and SAST targets, sorted by name", () => {
    const jobs = repositoryReportJobs([
      target("3", "web", TRIVY_MODE.SAST),
      target("1", "api", TRIVY_MODE.REPO),
      target("2", "infra", TRIVY_MODE.IAC),
      target("4", "image", TRIVY_MODE.IMAGE),
      target("5", "web", TRIVY_MODE.REPO),
    ]);
    expect(jobs).toEqual([
      { targetId: "1", targetName: "api", reportType: "sca" },
      { targetId: "3", targetName: "web", reportType: "sast" },
      { targetId: "5", targetName: "web", reportType: "sca" },
    ]);
  });
});

describe("report progress", () => {
  it("treats completed and failed runs as finished", () => {
    expect(isFinishedReportStatus("completed")).toBe(true);
    expect(isFinishedReportStatus("failed")).toBe(true);
    expect(isFinishedReportStatus("running")).toBe(false);
  });

  it("describes progress and failures", () => {
    expect(describeReportProgress({ total: 4, ready: 1, failed: 0 })).toBe(
      "Preparing reports: 1 of 4",
    );
    expect(describeReportProgress({ total: 4, ready: 3, failed: 1 })).toBe(
      "3 of 4 reports downloaded (1 failed)",
    );
  });
});

describe("runWithConcurrency", () => {
  it("runs every item without exceeding the limit", async () => {
    let inFlight = 0;
    let peak = 0;
    const seen: number[] = [];
    await runWithConcurrency([1, 2, 3, 4, 5], 2, async (item) => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 1));
      seen.push(item);
      inFlight -= 1;
    });
    expect(seen.sort()).toEqual([1, 2, 3, 4, 5]);
    expect(peak).toBe(2);
  });

  it("stops picking new items once asked to stop", async () => {
    const seen: number[] = [];
    await runWithConcurrency(
      [1, 2, 3],
      1,
      async (item) => {
        seen.push(item);
      },
      () => seen.length >= 1,
    );
    expect(seen).toEqual([1]);
  });
});
