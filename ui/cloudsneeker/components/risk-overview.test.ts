import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const read = (...segments: string[]) =>
  readFileSync(path.join(currentDir, ...segments), "utf8");

describe("Overview risk view wiring", () => {
  const source = read("risk-overview.tsx");
  const overviewPage = read("..", "..", "app", "(prowler)", "page.tsx");

  it("reads the newest executive report run and its stored data", () => {
    expect(source).toContain("listReportRuns");
    expect(source).toContain('"filter[report_type]": REPORT_TYPE_ID.EXECUTIVE');
    expect(source).toContain("getReportRunData");
    expect(source).toContain("latestCompletedRun");
    expect(source).toContain('isCloudsneekerFeatureEnabled("reports")');
  });

  it("is registered on the Overview page through marked hook lines", () => {
    expect(overviewPage).toMatch(
      /import \{ RiskOverview \} from "@\/cloudsneeker\/components\/risk-overview"; \/\/ cloudsneeker-hook/,
    );
    expect(overviewPage).toMatch(/cloudsneeker-hook[^\n]*\*\/\}\s*<RiskOverview \/>/);
    expect(overviewPage.indexOf("<RiskOverview />")).toBeLessThan(
      overviewPage.indexOf("<ThreatScoreSSR"),
    );
  });
});
