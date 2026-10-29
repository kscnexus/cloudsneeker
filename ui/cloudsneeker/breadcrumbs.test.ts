import { describe, expect, it } from "vitest";

import { BRAND } from "./brand";
import { breadcrumbSegmentLabel, ID_SEGMENT_LABEL } from "./breadcrumbs";

describe("breadcrumbSegmentLabel", () => {
  it("labels UUID segments as details", () => {
    expect(
      breadcrumbSegmentLabel(
        "608dcc5d-53e8-40f8-8d90-34c7533a866b",
        "608dcc5d 53e8 40f8 8d90 34c7533a866b",
      ),
    ).toBe(ID_SEGMENT_LABEL);
  });

  it("keeps the generated label for named segments", () => {
    expect(breadcrumbSegmentLabel("runs", "Runs")).toBe("Runs");
    expect(breadcrumbSegmentLabel("attack-paths", "Attack Paths")).toBe(
      "Attack Paths",
    );
  });

  it("uses product names for product areas", () => {
    expect(
      breadcrumbSegmentLabel("application-security", "Application Security"),
    ).toBe(BRAND.appSecurityName);
    expect(breadcrumbSegmentLabel("governance", "Governance")).toBe(
      BRAND.governanceName,
    );
  });
});
