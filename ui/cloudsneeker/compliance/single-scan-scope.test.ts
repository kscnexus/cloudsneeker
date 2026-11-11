import { describe, expect, it } from "vitest";

import {
  complianceScanFilters,
  complianceScope,
  eligibleComplianceScans,
  newestScanOfAccount,
  newestScanOfType,
  type ScopeScan,
} from "./single-scan-scope";

const scan = (
  id: string,
  provider: string,
  account: string,
  completed: string,
): ScopeScan => ({
  id,
  attributes: { completed_at: completed, name: id },
  providerInfo: { provider, uid: `${account}-uid`, alias: account },
  relationships: { provider: { data: { id: account } } },
});

const SCANS = [
  scan("aws-old", "aws", "prod", "2026-11-01T00:00:00Z"),
  scan("aws-new", "aws", "prod", "2026-11-05T00:00:00Z"),
  scan("aws-dev", "aws", "dev", "2026-11-03T00:00:00Z"),
  scan("azure-1", "azure", "sub", "2026-11-02T00:00:00Z"),
  scan("m365-1", "m365", "tenant", "2026-11-02T00:00:00Z"),
  scan("repo-1", "iac", "repo", "2026-11-06T00:00:00Z"),
  scan("img-1", "image", "registry", "2026-11-06T00:00:00Z"),
];

describe("eligibleComplianceScans", () => {
  it("drops code and image scans and application scan ids", () => {
    const ids = eligibleComplianceScans(SCANS, new Set(["azure-1"])).map(
      (item) => item.id,
    );
    expect(ids).toEqual(["aws-old", "aws-new", "aws-dev", "m365-1"]);
  });

  it("asks the API for compliance providers only", () => {
    const filter = complianceScanFilters()["filter[provider_type__in]"];
    expect(filter).toContain("aws");
    expect(filter).not.toContain("iac");
    expect(filter).not.toContain("image");
  });
});

describe("complianceScope", () => {
  const eligible = eligibleComplianceScans(SCANS);

  it("groups providers and narrows accounts and scans", () => {
    const scope = complianceScope(eligible, "aws-old");
    expect(scope.cloudProviders.map((item) => item.value)).toEqual([
      "aws",
      "azure",
    ]);
    expect(scope.saasProviders.map((item) => item.value)).toEqual(["m365"]);
    expect(scope.providerType).toBe("aws");
    expect(scope.accounts.map((item) => item.value)).toEqual(["dev", "prod"]);
    expect(scope.scans).toEqual(["aws-new", "aws-old"]);
  });

  it("has no account or scans without a selection", () => {
    const scope = complianceScope(eligible, null);
    expect(scope.providerType).toBeNull();
    expect(scope.accounts).toEqual([]);
    expect(scope.scans).toEqual([]);
  });

  it("picks the newest scan when the provider or account changes", () => {
    expect(newestScanOfType(eligible, "aws")).toBe("aws-new");
    expect(newestScanOfAccount(eligible, "dev")).toBe("aws-dev");
    expect(newestScanOfType(eligible, "gcp")).toBeNull();
  });
});
