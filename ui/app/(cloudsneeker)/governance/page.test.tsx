import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Cloud Governance page workspace", () => {
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

  it("uses the product name and product routes", () => {
    expect(source).toContain("title={BRAND.governanceName}");
    expect(source).toContain('governanceHref("new")');
    expect(source).not.toMatch(/"\/custodian|`\/custodian/);
    // Engine names only appear inside identifiers, never as words.
    expect(source).not.toMatch(/(Trivy|Custodian)/);
  });
});
