import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Custodian page workspace", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(path.join(currentDir, "page.tsx"), "utf8");

  it("wires dashboard, policies, and reports tabs", () => {
    expect(source).toContain("CustodianPageTabs");
    expect(source).toContain("CustodianDashboardPanel");
    expect(source).toContain("CustodianPolicyList");
    expect(source).toContain("CustodianReportsTable");
    expect(source).toContain("getCustodianTab");
    expect(source).toContain("buildCustodianDashboard");
    expect(source).toContain("buildCustodianReportRows");
  });
});
