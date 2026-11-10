import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Security scanning centre page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(path.join(currentDir, "page.tsx"), "utf8");

  it("lists current scans with URL filters", () => {
    expect(source).toContain("parseScanFilters");
    expect(source).toContain("listTrivyRuns(scanRunsQuery(filters))");
    expect(source).toContain("SCAN_FILTER_PARAM.STATUS");
    expect(source).toContain("SCAN_FILTER_PARAM.TYPE");
    expect(source).toContain("SCAN_FILTER_PARAM.TRIGGER");
    expect(source).toContain("SCAN_FILTER_PARAM.APPLICATION");
  });

  it("counts scans per status for the chips", () => {
    expect(source).toContain("loadStatusCounts");
    expect(source).toContain('aria-label="Scan status"');
  });

  it("links each scan and shows timing and findings", () => {
    expect(source).toContain(
      'appSecurityHref(attributes.target_id, "runs", run.id)',
    );
    expect(source).toContain("<RunStatusBadge");
    expect(source).toContain("formatDuration(runDurationMs(run))");
    expect(source).toContain("runFindingCount(run)");
    expect(source).toContain("errorSnippet(");
    expect(source).toContain("TABLE_FRAME_CLASS");
  });

  it("pages with Previous and Next and links the archive", () => {
    expect(source).toContain("Previous");
    expect(source).toContain("Next");
    expect(source).toContain("archivedScansHref()");
    expect(source).toContain("Scans could not be loaded");
  });

  it("uses the product name and no engine words", () => {
    expect(source).toContain("BRAND.appSecurityName");
    expect(source).not.toMatch(/"\/trivy|`\/trivy/);
    expect(source).not.toMatch(
      /\b(Trivy|Custodian|OpenGrep|Semgrep|Prowler)\b/,
    );
  });
});
