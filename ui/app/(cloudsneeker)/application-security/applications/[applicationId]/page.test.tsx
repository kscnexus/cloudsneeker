import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Application detail page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(path.join(currentDir, "page.tsx"), "utf8");

  it("loads the application's targets and 404s when it has none", () => {
    expect(source).toContain(
      'loadAllTargets({ "filter[provider]": applicationId })',
    );
    expect(source).toContain("isApplicationId(applicationId)");
    expect(source).toContain("notFound()");
    expect(source).toContain("Application could not be loaded");
  });

  it("keeps the tabs in the URL", () => {
    expect(source).toContain("<ProductPageTabs");
    expect(source).toContain("getApplicationTab");
    for (const tab of ["OVERVIEW", "TARGETS", "FINDINGS", "SCANS"]) {
      expect(source).toContain(`APPLICATION_TAB.${tab}`);
    }
  });

  it("drills into findings by category, priority and overdue", () => {
    expect(source).toContain("securityCategoryTabs");
    expect(source).toContain("category: tab.category");
    expect(source).toContain("{ priority }");
    expect(source).toContain('overdue: "1"');
    expect(source).toContain("Open all findings");
  });

  it("lists targets and the latest current scans", () => {
    expect(source).toContain("<TrivyTargetList");
    expect(source).toContain("newTargetHref(id)");
    expect(source).toContain("<AppSecurityRunList");
    expect(source).toContain('"filter[provider]": id');
    expect(source).toContain('"filter[archived]": "false"');
    expect(source).toContain("reportsHref()");
  });

  it("uses the product name and no engine words", () => {
    expect(source).toContain("BRAND.appSecurityName");
    expect(source).not.toMatch(
      /\b(Trivy|Custodian|OpenGrep|Semgrep|Prowler)\b/,
    );
  });
});
