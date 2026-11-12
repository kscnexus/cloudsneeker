import { describe, expect, it } from "vitest";

import { FINDING_AREA } from "@/cloudsneeker/types/area-findings";

import {
  AREA_CONFIG,
  AREA_FINDING_SORT,
  areaFindingHref,
  areaFindingsPageHref,
  areaFindingsSearchParams,
  hasLegacyAreaParams,
  areaSortOptions,
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

  it("sends the known exploited filter only for CVE areas", () => {
    const params = parseAreaFilters({ exploited: "1" });
    expect(params.exploited).toBe(true);
    expect(
      areaFindingsSearchParams(FINDING_AREA.APPLICATION_SECURITY, params)[
        "filter[known_exploited]"
      ],
    ).toBe("true");
    expect(
      areaFindingsSearchParams(FINDING_AREA.CLOUD, params)[
        "filter[known_exploited]"
      ],
    ).toBeUndefined();
    expect(
      areaFindingsPageHref(FINDING_AREA.APPLICATION_SECURITY, {
        exploited: true,
        sort: AREA_FINDING_SORT.EXPLOIT,
      }),
    ).toBe("/application-security/findings?sort=-epss&exploited=1");
  });

  it("offers the exploit sort only where findings are CVEs", () => {
    expect(areaSortOptions(FINDING_AREA.APPLICATION_SECURITY)).toContain(
      AREA_FINDING_SORT.EXPLOIT,
    );
    expect(areaSortOptions(FINDING_AREA.GOVERNANCE)).not.toContain(
      AREA_FINDING_SORT.EXPLOIT,
    );
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
    ).toBe(
      "/governance/findings?filter%5Bseverity__in%5D=high&filter%5Btriage_status__in%5D=resolved&page=2",
    );
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
    ).toBe("/application-security/findings/trivy-repo-CVE-1");
    expect(
      areaFindingHref(FINDING_AREA.GOVERNANCE, {
        uid: "custodian-p1-arn:aws:s3:::b/1",
        checkId: "r",
      }),
    ).toBe("/governance/findings/custodian-p1-arn%3Aaws%3As3%3A%3A%3Ab%2F1");
  });
});

describe("toggleSeverity", () => {
  it("adds in severity order and removes", () => {
    expect(toggleSeverity(["low"], "critical")).toEqual(["critical", "low"]);
    expect(toggleSeverity(["critical", "low"], "low")).toEqual(["critical"]);
  });
});

describe("account, region, resource type and muted filters", () => {
  it("round-trip through the URL and reach the API query", () => {
    const filters = parseAreaFilters({
      account: "prov-1",
      region: "eu-west-1",
      rtype: "aws.security-group",
      muted: "1",
    });
    expect(filters).toMatchObject({
      account: "prov-1",
      region: "eu-west-1",
      resourceType: "aws.security-group",
      muted: true,
    });
    expect(areaFindingsPageHref(FINDING_AREA.GOVERNANCE, filters)).toBe(
      "/governance/findings?filter%5Bprovider__in%5D=prov-1&filter%5Bregion__in%5D=eu-west-1&filter%5Bresource_type__in%5D=aws.security-group&filter%5Bmuted%5D=include",
    );
    expect(
      areaFindingsSearchParams(FINDING_AREA.GOVERNANCE, filters),
    ).toMatchObject({
      "filter[provider__in]": "prov-1",
      "filter[region__in]": "eu-west-1",
      "filter[resource_type__in]": "aws.security-group",
      "filter[muted]": "include",
    });
  });

  it("sends region and resource type for governance only", () => {
    const query = areaFindingsSearchParams(
      FINDING_AREA.CLOUD,
      parseAreaFilters({ region: "eu-west-1", rtype: "x", account: "p" }),
    );
    expect(query).not.toHaveProperty("filter[region__in]");
    expect(query).not.toHaveProperty("filter[resource_type__in]");
    expect(query["filter[provider__in]"]).toBe("p");
  });
});

describe("filter bar parameters", () => {
  it("reads the filter[...] names with several values each", () => {
    const filters = parseAreaFilters({
      "filter[severity__in]": "high,critical,bogus",
      "filter[triage_status__in]": "open,resolved,nope",
      "filter[source__in]": "p1,p2",
      "filter[provider__in]": "a,b",
      "filter[region__in]": "us-east-1,eu-west-1",
      "filter[search]": " bucket ",
      "filter[muted]": "include",
      pageSize: "50",
    });
    expect(filters).toMatchObject({
      severities: ["high", "critical"],
      triage: "open,resolved",
      source: "p1,p2",
      account: "a,b",
      region: "us-east-1,eu-west-1",
      search: "bucket",
      muted: true,
      pageSize: 50,
    });
    expect(
      areaFindingsSearchParams(FINDING_AREA.GOVERNANCE, filters),
    ).toMatchObject({
      "filter[triage_status__in]": "open,resolved",
      "filter[source__in]": "p1,p2",
      "page[size]": "50",
    });
  });

  it("caps the page size and flags legacy names", () => {
    expect(parseAreaFilters({ pageSize: "500" }).pageSize).toBe(100);
    expect(parseAreaFilters({ pageSize: "25" }).pageSize).toBeUndefined();
    expect(hasLegacyAreaParams({ severity: "high" })).toBe(true);
    expect(hasLegacyAreaParams({ "filter[severity__in]": "high" })).toBe(false);
  });
});
