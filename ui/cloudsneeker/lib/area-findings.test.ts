import { describe, expect, it } from "vitest";

import { FINDING_AREA } from "@/cloudsneeker/types/area-findings";

import {
  AREA_CONFIG,
  AREA_FINDING_SORT,
  areaFindingHref,
  areaFindingsPageHref,
  areaFindingsSearchParams,
  areaTriagePageHref,
  areaTriageSearchParams,
  parseAreaFilters,
  toggleSeverity,
} from "./area-findings";

describe("AREA_CONFIG", () => {
  it("keeps each area on its own pages", () => {
    expect(AREA_CONFIG.cloud.findingsHref).toBe("/findings");
    expect(AREA_CONFIG.cloud.triageHref).toBe("/triage");
    expect(AREA_CONFIG.application_security.findingsHref).toBe(
      "/application-security/findings",
    );
    expect(AREA_CONFIG.application_security.triageHref).toBe(
      "/application-security/triage",
    );
    expect(AREA_CONFIG.governance.findingsHref).toBe("/governance/findings");
    expect(AREA_CONFIG.governance.triageHref).toBe("/governance/triage");
  });

  it("labels columns for the area's data", () => {
    expect(AREA_CONFIG.application_security.checkLabel).toBe("Rule or CVE");
    expect(AREA_CONFIG.application_security.sourceLabel).toBe("Target");
    expect(AREA_CONFIG.governance.sourceLabel).toBe("Policy");
  });
});

describe("parseAreaFilters", () => {
  it("reads known values and drops the rest", () => {
    expect(
      parseAreaFilters({
        severity: "HIGH,bogus,critical,high",
        triage: "under_review",
        source: "target-1",
        q: "  lodash ",
        sort: "-last_seen_at",
        page: "3",
        fix: "available",
      }),
    ).toEqual({
      severities: ["high", "critical"],
      triage: "under_review",
      source: "target-1",
      search: "lodash",
      sort: AREA_FINDING_SORT.NEWEST,
      page: 3,
      fix: "available",
    });
  });

  it("falls back to defaults", () => {
    expect(
      parseAreaFilters({
        triage: "done",
        sort: "uid",
        page: "-1",
        fix: "maybe",
      }),
    ).toEqual({
      severities: [],
      triage: null,
      source: null,
      search: "",
      sort: AREA_FINDING_SORT.SEVERITY,
      page: 1,
      fix: null,
    });
  });
});

describe("areaFindingsSearchParams", () => {
  it("builds the API query for one area", () => {
    expect(
      areaFindingsSearchParams(FINDING_AREA.GOVERNANCE, {
        severities: ["critical", "high"],
        triage: "open",
        source: "policy-1",
        search: "vol",
        sort: AREA_FINDING_SORT.SEVERITY,
        page: 2,
        fix: "available",
      }),
    ).toEqual({
      "filter[area]": "governance",
      "page[number]": "2",
      "page[size]": "25",
      sort: "severity",
      "filter[severity__in]": "critical,high",
      "filter[triage_status__in]": "open",
      "filter[source__in]": "policy-1",
      "filter[search]": "vol",
    });
  });

  it("sends the fix filter only for areas with fix data", () => {
    const filters = {
      severities: [],
      triage: null,
      source: null,
      search: "",
      sort: AREA_FINDING_SORT.SEVERITY,
      page: 1,
      fix: "unavailable" as const,
    };
    expect(
      areaFindingsSearchParams(FINDING_AREA.APPLICATION_SECURITY, filters)[
        "filter[fix]"
      ],
    ).toBe("unavailable");
    expect(
      areaFindingsPageHref(FINDING_AREA.APPLICATION_SECURITY, filters),
    ).toBe("/application-security/findings?fix=unavailable");
  });

  it("scopes the triage list to the area", () => {
    expect(
      areaTriageSearchParams(FINDING_AREA.APPLICATION_SECURITY, null, 1),
    ).toEqual({
      "filter[area]": "application_security",
      "page[number]": "1",
      "page[size]": "25",
      sort: "-updated_at",
    });
  });
});

describe("area links", () => {
  it("leaves defaults out of the findings link", () => {
    expect(
      areaFindingsPageHref(FINDING_AREA.APPLICATION_SECURITY, {
        severities: [],
        sort: AREA_FINDING_SORT.SEVERITY,
        page: 1,
      }),
    ).toBe("/application-security/findings");
    expect(
      areaFindingsPageHref(FINDING_AREA.GOVERNANCE, {
        severities: ["high"],
        triage: "resolved",
        page: 2,
      }),
    ).toBe("/governance/findings?severity=high&triage=resolved&page=2");
  });

  it("keeps the cloud triage query names", () => {
    expect(areaTriagePageHref(FINDING_AREA.CLOUD, "resolved")).toBe(
      "/triage?status=resolved",
    );
    expect(areaTriagePageHref(FINDING_AREA.GOVERNANCE, null, 2)).toBe(
      "/governance/triage?page=2",
    );
  });

  it("opens cloud findings by check and the other areas by UID", () => {
    expect(
      areaFindingHref(FINDING_AREA.CLOUD, { uid: "u-1", checkId: "s3_x" }),
    ).toBe("/findings?filter%5Bcheck_id__in%5D=s3_x");
    expect(
      areaFindingHref(FINDING_AREA.APPLICATION_SECURITY, {
        uid: "trivy-repo-CVE-1",
        checkId: "CVE-1",
      }),
    ).toBe("/application-security/findings?q=trivy-repo-CVE-1");
  });
});

describe("toggleSeverity", () => {
  it("adds in severity order and removes", () => {
    expect(toggleSeverity(["low"], "critical")).toEqual(["critical", "low"]);
    expect(toggleSeverity(["critical", "low"], "low")).toEqual(["critical"]);
  });
});
