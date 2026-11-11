import { describe, expect, it } from "vitest";

import {
  actionError,
  APPSEC_FINDING_SORT,
  APPSEC_RESERVED_SEGMENTS,
  APPSEC_SEGMENT,
  APPSEC_WORKSPACES,
  appSecDownloadHref,
  appSecFindingLocation,
  appSecFindingsHref,
  appSecFindingsQuery,
  appSecFixSummary,
  appSecSeverityLabel,
  attributesOf,
  daysUntil,
  DEFAULT_APPSEC_FINDING_FILTERS,
  dueLabel,
  formatAppSecDate,
  isAppSecFiltered,
  parseAppSecFindingFilters,
  sumCounts,
  toggleItem,
  workspaceForCategory,
  workspaceForSegment,
} from "./appsec";

describe("workspaces", () => {
  it("has one workspace per category plus all findings", () => {
    expect(APPSEC_WORKSPACES.map((item) => item.category)).toEqual([
      "vulnerability",
      "misconfiguration",
      "secret",
      "license",
      "code",
      null,
    ]);
    expect(workspaceForSegment("secrets")?.category).toBe("secret");
    expect(workspaceForSegment("nope")).toBeUndefined();
    expect(workspaceForCategory("license").segment).toBe("licenses");
    expect(workspaceForCategory("mystery").segment).toBe("findings");
  });

  it("reserves every static segment", () => {
    for (const segment of Object.values(APPSEC_SEGMENT)) {
      expect(APPSEC_RESERVED_SEGMENTS).toContain(segment);
    }
    expect(APPSEC_RESERVED_SEGMENTS).toContain("new");
    expect(APPSEC_RESERVED_SEGMENTS).toContain("triage");
  });
});

describe("finding filters", () => {
  it("parses search params and drops unknown values", () => {
    const filters = parseAppSecFindingFilters({
      severity: "high,critical,bogus",
      state: "fixed",
      priority: ["urgent"],
      triage: "risk_accepted",
      fix: "available",
      overdue: "1",
      target: " t-1 ",
      q: "lodash",
      sort: "-severity",
      page: "3",
    });
    expect(filters.severities).toEqual(["critical", "high"]);
    expect(filters.states).toEqual(["fixed"]);
    expect(filters.priorities).toEqual(["urgent"]);
    expect(filters.triage).toBe("risk_accepted");
    expect(filters.fix).toBe("available");
    expect(filters.overdue).toBe(true);
    expect(filters.target).toBe("t-1");
    expect(filters.sort).toBe("-severity");
    expect(filters.page).toBe(3);
  });

  it("falls back to defaults", () => {
    expect(
      parseAppSecFindingFilters({ sort: "drop table", page: "-2", fix: "x" }),
    ).toEqual(DEFAULT_APPSEC_FINDING_FILTERS);
    expect(isAppSecFiltered(DEFAULT_APPSEC_FINDING_FILTERS)).toBe(false);
    expect(
      isAppSecFiltered({ ...DEFAULT_APPSEC_FINDING_FILTERS, search: "x" }),
    ).toBe(true);
  });

  it("round-trips through the page URL", () => {
    const filters = {
      ...DEFAULT_APPSEC_FINDING_FILTERS,
      severities: ["critical" as const],
      fix: "none" as const,
      pkg: "lodash",
      sort: APPSEC_FINDING_SORT.DUE,
      page: 2,
    };
    const href = appSecFindingsHref(APPSEC_SEGMENT.VULNERABILITIES, filters);
    expect(href.startsWith("/application-security/vulnerabilities?")).toBe(
      true,
    );
    const params = Object.fromEntries(
      new URLSearchParams(href.split("?")[1]).entries(),
    );
    expect(parseAppSecFindingFilters(params)).toEqual(filters);
    expect(appSecFindingsHref(APPSEC_SEGMENT.SECRETS)).toBe(
      "/application-security/secrets",
    );
  });

  it("builds the API query", () => {
    const query = appSecFindingsQuery("vulnerability", {
      ...DEFAULT_APPSEC_FINDING_FILTERS,
      severities: ["critical", "high"],
      fix: "available",
      overdue: true,
      rule: "CVE-2024-1",
      page: 2,
    });
    expect(query).toEqual({
      "filter[category]": "vulnerability",
      "filter[severity__in]": "critical,high",
      "filter[fix_available]": "true",
      "filter[overdue]": "true",
      "filter[rule_id]": "CVE-2024-1",
      sort: "-priority",
      "page[number]": "2",
      "page[size]": "25",
    });
    const all = appSecFindingsQuery(null, DEFAULT_APPSEC_FINDING_FILTERS, {
      paginate: false,
    });
    expect(all).toEqual({ sort: "-priority" });
  });

  it("toggles list items", () => {
    expect(toggleItem(["a", "b"], "a")).toEqual(["b"]);
    expect(toggleItem(["a"], "b")).toEqual(["a", "b"]);
  });
});

describe("presentation", () => {
  const base = {
    category: "vulnerability" as const,
    pkg_name: "",
    pkg_version: "",
    file_path: "",
    start_line: null,
    resource: "",
    location: "",
  };

  it("describes where a finding is", () => {
    expect(
      appSecFindingLocation({
        ...base,
        pkg_name: "lodash",
        pkg_version: "4.17.20",
      }),
    ).toBe("lodash 4.17.20");
    expect(
      appSecFindingLocation({ ...base, file_path: "main.tf", start_line: 12 }),
    ).toBe("main.tf:12");
    expect(appSecFindingLocation({ ...base, file_path: ".env" })).toBe(".env");
    expect(appSecFindingLocation({ ...base, resource: "ns/Pod/api" })).toBe(
      "ns/Pod/api",
    );
  });

  it("summarizes the fix only for vulnerabilities", () => {
    expect(
      appSecFixSummary({
        category: "vulnerability",
        fixed_version: "1.2",
        fix_available: true,
      }),
    ).toBe("Fix: 1.2");
    expect(
      appSecFixSummary({
        category: "vulnerability",
        fixed_version: "",
        fix_available: false,
      }),
    ).toBe("No fix yet");
    expect(
      appSecFixSummary({
        category: "secret",
        fixed_version: "",
        fix_available: null,
      }),
    ).toBe("");
  });

  it("labels and dates", () => {
    expect(appSecSeverityLabel("unknown")).toBe("Unknown");
    expect(appSecSeverityLabel("custom_level")).toBe("Custom level");
    expect(formatAppSecDate("2026-11-01T10:20:30Z")).toBe("2026-11-01 10:20");
    expect(formatAppSecDate(null)).toBe("–");
    expect(formatAppSecDate("nonsense")).toBe("–");
    const now = new Date("2026-11-10T00:00:00Z");
    expect(daysUntil("2026-11-13T00:00:00Z", now)).toBe(3);
    expect(dueLabel("2026-11-13T00:00:00Z", now)).toBe("Due in 3 d");
    expect(dueLabel("2026-11-08T00:00:00Z", now)).toBe("Overdue by 2 d");
    expect(dueLabel(null, now)).toBe("–");
  });

  it("builds download links", () => {
    expect(appSecDownloadHref("sbom", "cyclonedx", { id: "s-1" })).toBe(
      "/api/cloudsneeker/appsec/download?kind=sbom&format=cyclonedx&id=s-1",
    );
  });

  it("reads responses", () => {
    expect(sumCounts({ critical: 2, high: 3, low: 1 })).toBe(6);
    expect(sumCounts({ critical: 2, high: 3 }, ["critical"])).toBe(2);
    expect(sumCounts(undefined)).toBe(0);
    expect(attributesOf({ data: { attributes: { a: 1 } } })).toEqual({ a: 1 });
    expect(attributesOf({ data: [] })).toBeNull();
    expect(attributesOf({ error: "x" })).toBeNull();
    expect(actionError({ data: {} })).toBeNull();
    expect(actionError({ error: "Denied", status: 403 })).toBe("Denied");
    expect(actionError({ errors: [{ detail: "Bad name" }] })).toBe("Bad name");
    expect(actionError(undefined)).toBeNull();
  });
});
