import { describe, expect, it, vi } from "vitest";

import { BRAND, checkDocsUrl, docsUrl } from "./brand";

type BrandModule = typeof import("./brand");

describe("BRAND", () => {
  it("never mentions the upstream project", () => {
    for (const [key, value] of Object.entries(BRAND)) {
      if (typeof value === "string") {
        expect(value.toLowerCase(), key).not.toContain("prowler");
      }
    }
  });

  it("names product areas without engine names", () => {
    expect(BRAND.appSecurityName).toBe("Application Security");
    expect(BRAND.governanceName).toBe("Cloud Governance");
    for (const value of [
      BRAND.cloudSecurityName,
      BRAND.appSecurityName,
      BRAND.governanceName,
    ]) {
      expect(value).not.toMatch(/trivy|custodian|c7n|prowler/i);
    }
  });

  it("hides hosted-tier upsell in the shipped config", async () => {
    // vitest.setup.ts enables upsell for upstream suites; read the real module.
    const actual = await vi.importActual<BrandModule>("./brand");
    expect(actual.BRAND.showUpsell).toBe(false);
  });

  it("hides documentation hyperlinks in the shipped config", async () => {
    const actual = await vi.importActual<BrandModule>("./brand");
    expect(actual.BRAND.showDocumentationLinks).toBe(false);
  });
});

describe("docsUrl", () => {
  it("returns the base without a path", () => {
    expect(docsUrl()).toBe(BRAND.docsUrl);
  });

  it("joins paths with a single slash", () => {
    expect(docsUrl("/user-guide")).toBe(`${BRAND.docsUrl}/user-guide`);
    expect(docsUrl("user-guide")).toBe(`${BRAND.docsUrl}/user-guide`);
  });
});

describe("checkDocsUrl", () => {
  it("builds the check reference page", () => {
    expect(checkDocsUrl("iam_avoid_root_usage")).toBe(
      `${BRAND.docsUrl}/checks/iam_avoid_root_usage`,
    );
  });
});
