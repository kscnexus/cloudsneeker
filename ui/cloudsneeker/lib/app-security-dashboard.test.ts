import { describe, expect, it } from "vitest";

import {
  TRIVY_MODE,
  TRIVY_RUN_STATUS,
  TRIVY_RUN_TRIGGER,
  type TrivyMode,
  type TrivyRunResource,
  type TrivyRunStatus,
  type TrivyTargetConfig,
  type TrivyTargetResource,
} from "@/cloudsneeker/types/trivy";

import {
  APP_SECURITY_CATEGORY,
  appSecurityCategoryHref,
  buildAppSecurityDashboard,
  filterTargetsByCategory,
  getAppSecurityCategory,
  latestCompletedRunByTarget,
  targetMatchesCategory,
} from "./app-security-dashboard";

const target = (
  id: string,
  mode: TrivyMode,
  config: TrivyTargetConfig = {},
  scheduled = false,
): TrivyTargetResource => ({
  id,
  type: "trivy-targets",
  attributes: {
    name: `Target ${id}`,
    description: "",
    mode,
    config,
    provider_id: "provider-1",
    schedule_enabled: scheduled,
  },
});

const run = (
  id: string,
  targetId: string,
  status: TrivyRunStatus,
  findingCount?: number,
  scanId = `scan-${id}`,
): TrivyRunResource => ({
  id,
  type: "trivy-runs",
  attributes: {
    target_id: targetId,
    target_name: `Target ${targetId}`,
    provider_id: "provider-1",
    status,
    trigger: TRIVY_RUN_TRIGGER.MANUAL,
    scan_id: status === TRIVY_RUN_STATUS.COMPLETED ? scanId : null,
    summary:
      findingCount === undefined ? {} : { finding_count: findingCount },
    inserted_at: "2026-10-28T09:00:00Z",
  },
});

describe("getAppSecurityCategory", () => {
  it("accepts known categories only", () => {
    expect(getAppSecurityCategory("code")).toBe(APP_SECURITY_CATEGORY.CODE);
    expect(getAppSecurityCategory(["sbom", "iac"])).toBe(
      APP_SECURITY_CATEGORY.SBOM,
    );
    expect(getAppSecurityCategory("unknown")).toBeNull();
    expect(getAppSecurityCategory(undefined)).toBeNull();
  });
});

describe("appSecurityCategoryHref", () => {
  it("adds the category to the hub route", () => {
    expect(appSecurityCategoryHref(APP_SECURITY_CATEGORY.SECRETS)).toBe(
      "/application-security?category=secrets",
    );
    expect(appSecurityCategoryHref(null)).toBe("/application-security");
  });
});

describe("targetMatchesCategory", () => {
  it("maps modes onto product areas", () => {
    expect(
      targetMatchesCategory(target("a", TRIVY_MODE.REPO), "dependencies"),
    ).toBe(true);
    expect(targetMatchesCategory(target("b", TRIVY_MODE.SAST), "code")).toBe(
      true,
    );
    expect(
      targetMatchesCategory(target("c", TRIVY_MODE.IMAGE), "containers"),
    ).toBe(true);
    expect(
      targetMatchesCategory(target("d", TRIVY_MODE.K8S), "kubernetes"),
    ).toBe(true);
    expect(targetMatchesCategory(target("e", TRIVY_MODE.SAST), "iac")).toBe(
      false,
    );
  });

  it("counts secrets only for targets that run the secret scanner", () => {
    expect(
      targetMatchesCategory(target("a", TRIVY_MODE.FS), "secrets"),
    ).toBe(true);
    expect(
      targetMatchesCategory(
        target("b", TRIVY_MODE.FS, { scanners: ["vuln"] }),
        "secrets",
      ),
    ).toBe(false);
    expect(targetMatchesCategory(target("c", TRIVY_MODE.SAST), "secrets")).toBe(
      false,
    );
  });
});

describe("filterTargetsByCategory", () => {
  it("returns every target without a category", () => {
    const targets = [target("a", TRIVY_MODE.IAC), target("b", TRIVY_MODE.SBOM)];

    expect(filterTargetsByCategory(targets, null)).toHaveLength(2);
    expect(
      filterTargetsByCategory(targets, "sbom").map((item) => item.id),
    ).toEqual(["b"]);
  });
});

describe("latestCompletedRunByTarget", () => {
  it("keeps the first completed run per target", () => {
    const latest = latestCompletedRunByTarget([
      run("r3", "a", TRIVY_RUN_STATUS.RUNNING),
      run("r2", "a", TRIVY_RUN_STATUS.COMPLETED, 4),
      run("r1", "a", TRIVY_RUN_STATUS.COMPLETED, 9),
    ]);

    expect(latest.get("a")?.id).toBe("r2");
  });
});

describe("buildAppSecurityDashboard", () => {
  it("totals targets, scans, findings and categories", () => {
    const targets = [
      target("a", TRIVY_MODE.REPO, {}, true),
      target("b", TRIVY_MODE.SAST),
      target("c", TRIVY_MODE.IMAGE),
    ];
    const runs = [
      run("r4", "c", TRIVY_RUN_STATUS.FAILED),
      run("r3", "b", TRIVY_RUN_STATUS.COMPLETED, 3),
      run("r2", "a", TRIVY_RUN_STATUS.PENDING),
      run("r1", "a", TRIVY_RUN_STATUS.COMPLETED, 7),
      run("r0", "gone", TRIVY_RUN_STATUS.COMPLETED, 100),
    ];

    const dashboard = buildAppSecurityDashboard({ targets, runs, runTotal: 42 });

    expect(dashboard).toMatchObject({
      targetCount: 3,
      scheduledTargetCount: 1,
      runCount: 42,
      activeRunCount: 1,
      failedRunCount: 1,
      latestFindingCount: 10,
    });
    expect(dashboard.latestScanIds.sort()).toEqual(["scan-r1", "scan-r3"]);
    expect(dashboard.lastRun).toMatchObject({
      runId: "r4",
      status: TRIVY_RUN_STATUS.FAILED,
      href: "/application-security/c/runs/r4",
    });

    const byId = Object.fromEntries(
      dashboard.categories.map((item) => [item.id, item]),
    );
    expect(byId.dependencies).toMatchObject({ targetCount: 1, findingCount: 7 });
    expect(byId.code).toMatchObject({ targetCount: 1, findingCount: 3 });
    expect(byId.containers).toMatchObject({
      targetCount: 1,
      findingCount: null,
    });
    expect(byId.secrets.targetCount).toBe(2);
    expect(byId.kubernetes.targetCount).toBe(0);
  });

  it("falls back to the loaded runs when the API sends no total", () => {
    expect(
      buildAppSecurityDashboard({ targets: [], runs: [], runTotal: null }),
    ).toMatchObject({ runCount: 0, lastRun: null, latestFindingCount: null });
  });
});
