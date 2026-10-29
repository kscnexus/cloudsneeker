import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const read = (file: string) =>
  readFileSync(path.join(currentDir, file), "utf8");

describe("Reports pages", () => {
  const listSource = read("page.tsx");
  const runSource = read(path.join("[runId]", "page.tsx"));

  it("loads the catalog, runs, schedules and share links", () => {
    expect(listSource).toContain("listReportTypes");
    expect(listSource).toContain("listReportRuns");
    expect(listSource).toContain("listReportSchedules");
    expect(listSource).toContain("listReportShareLinks");
    expect(listSource).toContain("ReportPageTabs");
    expect(listSource).toContain("ReportCatalogGrid");
    expect(listSource).toContain("ReportRunsTable");
  });

  it("reads providers and frameworks from the existing APIs", () => {
    expect(listSource).toContain("getProviders");
    expect(listSource).toContain("getCompliancesOverview");
  });

  it("gates sharing and schedules on manage_scans", () => {
    expect(listSource).toContain("manage_scans");
    expect(runSource).toContain("manage_scans");
  });

  it("renders the stored payload with downloads, share and print", () => {
    expect(runSource).toContain("getReportRunData");
    expect(runSource).toContain("ReportView");
    expect(runSource).toContain("ReportDownloadLinks");
    expect(runSource).toContain("ReportShareDialog");
    expect(runSource).toContain("ReportPrintButton");
    expect(runSource).toContain("AutoRefresh");
  });

  it("never names an engine", () => {
    for (const source of [listSource, runSource]) {
      expect(source).not.toMatch(/Trivy|Custodian|Prowler|OpenGrep|Semgrep/);
    }
  });
});
