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
  APP_SECURITY_TAB,
  appSecurityCategoryHref,
  appSecurityTabHref,
  buildAppSecurityDashboard,
  filterTargetsByCategory,
  getAppSecurityCategory,
  getAppSecurityTab,
  latestCompletedRunByTarget,
  newTargetHref,
  repositorySourcesWithoutTarget,
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
    summary: findingCount === undefined ? {} : { finding_count: findingCount },
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
  it("adds the category to the scans route, where targets are listed", () => {
    expect(appSecurityCategoryHref(APP_SECURITY_CATEGORY.SECRETS)).toBe(
      "/application-security/scans?category=secrets",
    );
    expect(appSecurityCategoryHref(null)).toBe("/application-security/scans");
  });
});

describe("Application Security tabs", () => {
  it("reads the tab, opening Targets for a category link", () => {
    expect(getAppSecurityTab("scans")).toBe(APP_SECURITY_TAB.SCANS);
    expect(getAppSecurityTab(["targets"])).toBe(APP_SECURITY_TAB.TARGETS);
    expect(getAppSecurityTab("bogus")).toBe(APP_SECURITY_TAB.DASHBOARD);
    expect(getAppSecurityTab(undefined)).toBe(APP_SECURITY_TAB.DASHBOARD);
    expect(getAppSecurityTab(undefined, APP_SECURITY_CATEGORY.SECRETS)).toBe(
      APP_SECURITY_TAB.TARGETS,
    );
  });

  it("links each tab, leaving the dashboard bare", () => {
    expect(appSecurityTabHref(APP_SECURITY_TAB.DASHBOARD)).toBe(
      "/application-security",
    );
    expect(appSecurityTabHref(APP_SECURITY_TAB.SCANS)).toBe(
      "/application-security?tab=scans",
    );
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

  it("counts repositories and archives under IaC when they scan misconfigurations", () => {
    expect(targetMatchesCategory(target("a", TRIVY_MODE.REPO), "iac")).toBe(
      true,
    );
    expect(targetMatchesCategory(target("b", TRIVY_MODE.IAC), "iac")).toBe(
      true,
    );
    expect(
      targetMatchesCategory(
        target("c", TRIVY_MODE.FS, { scanners: ["vuln", "secret"] }),
        "iac",
      ),
    ).toBe(false);
  });

  it("counts secrets only for targets that run the secret scanner", () => {
    expect(targetMatchesCategory(target("a", TRIVY_MODE.FS), "secrets")).toBe(
      true,
    );
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

    const dashboard = buildAppSecurityDashboard({
      targets,
      runs,
      runTotal: 42,
    });

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
    expect(byId.dependencies).toMatchObject({
      targetCount: 1,
      findingCount: 7,
    });
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

describe("newTargetHref", () => {
  it("links to the new-target page", () => {
    expect(newTargetHref()).toBe("/application-security/new");
  });

  it("preselects the given source", () => {
    expect(newTargetHref("p 1")).toBe(
      "/application-security/new?provider=p%201",
    );
  });
});

describe("repositorySourcesWithoutTarget", () => {
  const source = (id: string, providerType = "iac") => ({
    id,
    providerType,
    label: `Code repository � ${id}`,
  });

  it("offers connected repositories that no target scans", () => {
    const sources = [source("provider-1"), source("provider-2")];
    expect(
      repositorySourcesWithoutTarget(sources, [target("a", TRIVY_MODE.REPO)]),
    ).toEqual([source("provider-2")]);
  });

  it("offers every repository when there are no targets", () => {
    expect(repositorySourcesWithoutTarget([source("provider-1")], [])).toEqual([
      source("provider-1"),
    ]);
  });

  it("leaves out other source types", () => {
    expect(
      repositorySourcesWithoutTarget(
        [source("registry", "image"), source("aws", "aws")],
        [],
      ),
    ).toEqual([]);
  });
});
