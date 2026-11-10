import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Application Inventory page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(path.join(currentDir, "page.tsx"), "utf8");

  it("groups every target into applications with finding counts", () => {
    expect(source).toContain("loadAllTargets()");
    expect(source).toContain("loadApplicationSummaries()");
    expect(source).toContain("groupTargetsIntoApplications");
    expect(source).toContain("attachSummaries");
  });

  it("searches, sorts and pages in the URL", () => {
    expect(source).toContain("parseApplicationsQuery");
    expect(source).toContain("searchApplications");
    expect(source).toContain("sortApplications");
    expect(source).toContain("paginate(");
    expect(source).toContain('method="get"');
  });

  it("shows the inventory columns in a scrollable table", () => {
    for (const header of [
      '"Application"',
      '"Repository"',
      '"Scan types"',
      '"Targets"',
      '"Open findings"',
      '"Critical"',
      '"High"',
      '"Posture"',
    ]) {
      expect(source).toContain(header);
    }
    expect(source).toContain("TABLE_FRAME_CLASS");
    expect(source).toContain("applicationHref(application.id)");
  });

  it("shows a load error, not an empty list, when targets fail", () => {
    expect(source).toContain("Applications could not be loaded");
    expect(source.indexOf("if (!loaded)")).toBeLessThan(
      source.indexOf("No applications yet"),
    );
    expect(source).toContain('appSecurityHref("new")');
  });

  it("uses the product name and shared components", () => {
    expect(source).toContain("BRAND.appSecurityName");
    expect(source).toContain("<PageHeader");
    expect(source).toContain("<SectionCard");
    expect(source).not.toMatch(/"\/trivy|`\/trivy/);
    expect(source).not.toMatch(
      /\b(Trivy|Custodian|OpenGrep|Semgrep|Prowler)\b/,
    );
  });
});
