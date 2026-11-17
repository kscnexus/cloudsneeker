import { describe, expect, it } from "vitest";

import { APPSEC_CATEGORY } from "@/cloudsneeker/types/appsec";
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
  categoryDefinition,
  countAreaFindings,
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
      findingCounts: {
        a: { vulnerability: 5, secret: 2 },
        b: { code: 3 },
      },
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
      scannedTargetCount: 1,
      findingCount: 5,
    });
    expect(byId.code).toMatchObject({ targetCount: 1, findingCount: 3 });
    expect(byId.containers).toMatchObject({
      targetCount: 1,
      scannedTargetCount: 0,
      findingCount: 0,
    });
    expect(byId.secrets).toMatchObject({ targetCount: 2, findingCount: 2 });
    expect(byId.kubernetes.targetCount).toBe(0);
  });

  it("gives each area its own findings instead of every finding of its targets", () => {
    // A repository holds dependency, IaC, secret and license findings; each
    // area tile must show only its share, not the repository's total.
    const targets = [
      target("repo", TRIVY_MODE.REPO),
      target("fs", TRIVY_MODE.FS, { scanners: ["vuln"] }),
      target("image", TRIVY_MODE.IMAGE),
    ];
    const runs = [
      run("r3", "image", TRIVY_RUN_STATUS.COMPLETED, 9),
      run("r2", "fs", TRIVY_RUN_STATUS.COMPLETED, 4),
      run("r1", "repo", TRIVY_RUN_STATUS.COMPLETED, 1655),
    ];

    const dashboard = buildAppSecurityDashboard({
      targets,
      runs,
      findingCounts: {
        repo: {
          vulnerability: 300,
          misconfiguration: 120,
          secret: 30,
          license: 50,
        },
        fs: { vulnerability: 4 },
        image: { vulnerability: 6, secret: 1, misconfiguration: 2 },
      },
    });
    const count = (id: string) =>
      dashboard.categories.find((item) => item.id === id)?.findingCount;

    expect(count(APP_SECURITY_CATEGORY.DEPENDENCIES)).toBe(354);
    expect(count(APP_SECURITY_CATEGORY.IAC)).toBe(120);
    expect(count(APP_SECURITY_CATEGORY.SECRETS)).toBe(31);
    expect(count(APP_SECURITY_CATEGORY.CONTAINERS)).toBe(9);
    expect(count(APP_SECURITY_CATEGORY.CODE)).toBe(0);
  });

  it("leaves area counts unknown when the counts could not be loaded", () => {
    const dashboard = buildAppSecurityDashboard({
      targets: [target("a", TRIVY_MODE.REPO)],
      runs: [run("r1", "a", TRIVY_RUN_STATUS.COMPLETED, 12)],
      findingCounts: null,
    });
    const dependencies = dashboard.categories.find(
      (item) => item.id === APP_SECURITY_CATEGORY.DEPENDENCIES,
    );
    expect(dependencies).toMatchObject({
      scannedTargetCount: 1,
      findingCount: null,
    });
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

describe("countAreaFindings", () => {
  const counts = {
    a: { vulnerability: 3, license: 2, secret: 1 },
    b: { misconfiguration: 4 },
  };

  it("adds only the area's own categories", () => {
    const dependencies = categoryDefinition(APP_SECURITY_CATEGORY.DEPENDENCIES);
    const secrets = categoryDefinition(APP_SECURITY_CATEGORY.SECRETS);
    expect(dependencies?.findingCategories).toEqual([
      APPSEC_CATEGORY.VULNERABILITY,
      APPSEC_CATEGORY.LICENSE,
    ]);
    expect(countAreaFindings(dependencies!, ["a", "b"], counts)).toBe(5);
    expect(countAreaFindings(secrets!, ["a", "b"], counts)).toBe(1);
  });

  it("adds every category for an area defined by target type alone", () => {
    const containers = categoryDefinition(APP_SECURITY_CATEGORY.CONTAINERS);
    expect(containers?.findingCategories).toBeUndefined();
    expect(countAreaFindings(containers!, ["a", "b"], counts)).toBe(10);
  });

  it("counts nothing for targets without findings", () => {
    const iac = categoryDefinition(APP_SECURITY_CATEGORY.IAC);
    expect(countAreaFindings(iac!, ["missing"], counts)).toBe(0);
    expect(countAreaFindings(iac!, [], counts)).toBe(0);
  });
});
