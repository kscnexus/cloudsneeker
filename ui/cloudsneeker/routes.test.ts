import { describe, expect, it } from "vitest";

import {
  appSecurityHref,
  governanceHref,
  legacyRedirectHref,
  PRODUCT_ROUTE,
  reportDownloadHref,
  reportsHref,
  sharedReportHref,
} from "./routes";

describe("product routes", () => {
  it("never names an engine", () => {
    for (const route of Object.values(PRODUCT_ROUTE)) {
      expect(route).not.toMatch(/trivy|custodian|c7n|prowler/i);
    }
  });

  it("builds Application Security paths", () => {
    expect(appSecurityHref()).toBe("/application-security");
    expect(appSecurityHref("new")).toBe("/application-security/new");
    expect(appSecurityHref("t-1", "runs", "r-1")).toBe(
      "/application-security/t-1/runs/r-1",
    );
  });

  it("builds Cloud Governance paths", () => {
    expect(governanceHref()).toBe("/governance");
    expect(governanceHref("p-1", "edit")).toBe("/governance/p-1/edit");
  });

  it("builds Reports paths", () => {
    expect(reportsHref()).toBe("/reports");
    expect(reportsHref("run-1")).toBe("/reports/run-1");
    expect(sharedReportHref("tok_en-1")).toBe("/shared-reports/tok_en-1");
    expect(reportDownloadHref("run-1", "pdf")).toBe(
      "/api/cloudsneeker/reports/run-1/download?format=pdf",
    );
  });

  it("encodes path segments", () => {
    expect(governanceHref("a b")).toBe("/governance/a%20b");
  });
});

describe("legacyRedirectHref", () => {
  it("maps the old engine paths to the product routes", () => {
    expect(legacyRedirectHref("/trivy")).toBe("/application-security");
    expect(legacyRedirectHref("/custodian")).toBe("/governance");
  });

  it("keeps sub-paths and ids", () => {
    expect(legacyRedirectHref("/trivy", ["t-1", "runs", "r-1"])).toBe(
      "/application-security/t-1/runs/r-1",
    );
    expect(legacyRedirectHref("/custodian", ["p-1", "edit"])).toBe(
      "/governance/p-1/edit",
    );
  });

  it("keeps the query string", () => {
    expect(
      legacyRedirectHref("/custodian", ["new"], {
        template: "public-s3",
        empty: undefined,
      }),
    ).toBe("/governance/new?template=public-s3");
    expect(legacyRedirectHref("/custodian", [], { tab: ["reports"] })).toBe(
      "/governance?tab=reports",
    );
  });
});
