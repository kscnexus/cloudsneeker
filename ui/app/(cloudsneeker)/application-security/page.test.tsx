import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Application Security page workspace", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(path.join(currentDir, "page.tsx"), "utf8");

  it("renders the dashboard, then targets and recent runs", () => {
    expect(source).toContain("listTrivyTargets");
    expect(source).toContain("listTrivyRuns");
    expect(source).toContain("buildAppSecurityDashboard");
    expect(source).toContain("AppSecurityDashboardPanel");
    expect(source).toContain("TrivyTargetList");
    expect(source).toContain("AppSecurityRunList");
    expect(source).toContain("New target");
    expect(source.indexOf("<AppSecurityDashboardPanel")).toBeLessThan(
      source.indexOf("<TrivyTargetList"),
    );
  });

  it("shows a load error instead of an empty list when targets fail", () => {
    expect(source).toContain("isListResponse(targetsResponse)");
    expect(source).toContain("Targets could not be loaded");
  });

  it("filters targets by the category in the query", () => {
    expect(source).toContain("getAppSecurityCategory");
    expect(source).toContain("filterTargetsByCategory");
    expect(source).toContain("APP_SECURITY_CATEGORY_PARAM");
  });

  it("counts open findings per severity from the latest scans", () => {
    expect(source).toContain("getFindings");
    expect(source).toContain('"filter[scan__in]"');
    expect(source).toContain("REPORT_SEVERITY_ORDER");
  });

  it("uses the shared page components", () => {
    expect(source).toContain("<PageHeader");
    expect(source).toContain("<SectionCard");
  });

  it("uses the product name and product routes", () => {
    expect(source).toContain("title={BRAND.appSecurityName}");
    expect(source).toContain("appSecurityHref(");
    expect(source).not.toMatch(/"\/trivy|`\/trivy/);
    // Engine names only appear inside identifiers, never as words.
    expect(source).not.toMatch(/\b(Trivy|Custodian|OpenGrep|Semgrep|Prowler)\b/);
  });
});
