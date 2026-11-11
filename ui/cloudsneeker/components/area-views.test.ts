import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const read = (...segments: string[]) =>
  readFileSync(path.join(currentDir, ...segments), "utf8");

describe("Area triage view", () => {
  const source = read("area-triage-view.tsx");

  it("lists the area's triage filtered by status", () => {
    expect(source).toContain("listFindingTriages");
    expect(source).toContain("areaTriageSearchParams(area, status, page)");
    expect(source).toContain("<FindingTriageStatusFilter");
    expect(source).toContain(
      "<FindingTriageTable triages={triages} area={area}",
    );
  });

  it("shows a load error instead of an empty list when the request fails", () => {
    expect(source).toContain("isListResponse(response)");
    expect(source).toContain("Triage could not be loaded");
  });
});

describe("Area findings view", () => {
  const source = read("area-findings-view.tsx");

  it("lists the area's findings with filters and triage", () => {
    expect(source).toContain(
      "listAreaFindings(areaFindingsSearchParams(area, filters))",
    );
    expect(source).toContain("<AreaFindingsFilters");
    expect(source).toContain("<AreaFindingsTable");
  });

  it("only lets scan managers triage", () => {
    expect(source).toContain("permissions?.manage_scans");
  });

  it("shows a load error instead of an empty list when the request fails", () => {
    expect(source).toContain("Findings could not be loaded");
  });
});

describe("Area pages", () => {
  const appDir = path.join(currentDir, "..", "..", "app", "(cloudsneeker)");
  const page = (...segments: string[]) =>
    readFileSync(path.join(appDir, ...segments, "page.tsx"), "utf8");

  it.each([
    [
      ["application-security", "triage"],
      "AreaTriageView",
      "APPLICATION_SECURITY",
    ],
    [["governance", "findings"], "AreaFindingsView", "GOVERNANCE"],
    [["governance", "triage"], "AreaTriageView", "GOVERNANCE"],
  ])("%s renders %s for its own area", (segments, view, area) => {
    const source = page(...segments);
    expect(source).toContain(`<${view}`);
    expect(source).toContain(`FINDING_AREA.${area}`);
    expect(source).not.toMatch(/\bProwler\b/);
  });

  it("application-security findings uses the persistent findings workspace", () => {
    const source = page("application-security", "findings");
    expect(source).toContain("<AppSecFindingsWorkspace");
    expect(source).toContain("APPSEC_SEGMENT.FINDINGS");
    expect(source).not.toMatch(/\b(Prowler|Trivy)\b/);
  });
});
