import { describe, expect, it } from "vitest";

import type { AreaApplicationSummary } from "@/cloudsneeker/types/area-findings";
import type {
  TrivyMode,
  TrivyTargetResource,
} from "@/cloudsneeker/types/trivy";

import {
  type Application,
  APPLICATION_SORT,
  APPLICATION_TAB,
  applicationHref,
  applicationPostureLabel,
  applicationsHref,
  attachSummaries,
  getApplicationSort,
  getApplicationTab,
  groupTargetsIntoApplications,
  paginate,
  parseApplicationsQuery,
  responseApplicationSummaries,
  scanTypeLabels,
  searchApplications,
  sortApplications,
} from "./app-security-applications";

const target = (
  id: string,
  providerId: string,
  mode: TrivyMode,
  extra: Partial<TrivyTargetResource["attributes"]> = {},
): TrivyTargetResource => ({
  id,
  type: "trivy-targets",
  attributes: {
    name: id,
    description: "",
    mode,
    config: {},
    provider_id: providerId,
    ...extra,
  },
});

const app = (
  id: string,
  name: string,
  summary?: Omit<AreaApplicationSummary, "id">,
): Application => ({
  id,
  name,
  repository: `https://git.example.com/${name}`,
  modes: [],
  targets: [],
  summary: summary ? { id, ...summary } : undefined,
});

describe("groupTargetsIntoApplications", () => {
  it("groups targets by provider with distinct modes", () => {
    const applications = groupTargetsIntoApplications([
      target("t1", "p1", "repo", {
        provider_alias: "Shop",
        provider_uid: "https://git.example.com/shop",
      }),
      target("t2", "p1", "sast"),
      target("t3", "p1", "repo"),
      target("t4", "p2", "image", { provider_uid: "registry.example.com" }),
      target("t5", "", "repo"),
    ]);
    expect(applications).toHaveLength(2);
    expect(applications[0]).toMatchObject({
      id: "p1",
      name: "Shop",
      repository: "https://git.example.com/shop",
      modes: ["repo", "sast"],
    });
    expect(applications[0].targets.map((item) => item.id)).toEqual([
      "t1",
      "t2",
      "t3",
    ]);
    expect(applications[1]).toMatchObject({
      id: "p2",
      name: "registry.example.com",
      repository: "registry.example.com",
    });
    expect(scanTypeLabels(applications[0])).toEqual([
      "Code repository",
      "Static analysis",
    ]);
  });

  it("falls back to the provider id for the name", () => {
    expect(
      groupTargetsIntoApplications([target("t1", "p9", "fs")])[0].name,
    ).toBe("p9");
  });
});

describe("summaries", () => {
  it("reads meta.applications and attaches it by id", () => {
    const summaries = responseApplicationSummaries({
      data: [],
      meta: {
        applications: [
          { id: "a", total: 3, critical: 1, high: 1, urgent: 0 },
          null,
          { total: 1 },
        ],
      },
    });
    expect(summaries).toHaveLength(1);
    const [withSummary, withoutSummary] = attachSummaries(
      [app("a", "A"), app("b", "B")],
      summaries,
    );
    expect(withSummary.summary?.total).toBe(3);
    expect(withoutSummary.summary).toBeUndefined();
    expect(responseApplicationSummaries(null)).toEqual([]);
  });

  it("labels the posture", () => {
    expect(applicationPostureLabel(app("a", "A"))).toBe("Not scanned");
    expect(
      applicationPostureLabel(
        app("a", "A", { total: 2, critical: 0, high: 0, urgent: 1 }),
      ),
    ).toBe("Critical risk");
    expect(
      applicationPostureLabel(
        app("a", "A", { total: 0, critical: 0, high: 0, urgent: 0 }),
      ),
    ).toBe("No open findings");
  });
});

describe("searchApplications", () => {
  const applications = [app("1", "Payments"), app("2", "Storefront")];

  it("matches name or repository, ignoring case", () => {
    expect(searchApplications(applications, "PAY").map((a) => a.id)).toEqual([
      "1",
    ]);
    expect(
      searchApplications(applications, "example.com/store").map((a) => a.id),
    ).toEqual(["2"]);
  });

  it("returns everything for an empty search", () => {
    expect(searchApplications(applications, "  ")).toHaveLength(2);
    expect(searchApplications(applications, undefined)).toHaveLength(2);
  });
});

describe("sortApplications", () => {
  const applications = [
    app("quiet", "Quiet", { total: 50, critical: 0, high: 0, urgent: 0 }),
    app("crit", "Crit", { total: 2, critical: 2, high: 0, urgent: 0 }),
    app("urgent", "Urgent", { total: 1, critical: 0, high: 0, urgent: 1 }),
    app("high", "High", { total: 3, critical: 0, high: 3, urgent: 0 }),
    app("none", "alpha"),
  ];

  it("ranks by risk: urgent, critical, high, total", () => {
    expect(
      sortApplications(applications, APPLICATION_SORT.RISK).map((a) => a.id),
    ).toEqual(["urgent", "crit", "high", "quiet", "none"]);
  });

  it("sorts by name and by findings", () => {
    expect(
      sortApplications(applications, APPLICATION_SORT.NAME).map((a) => a.id),
    ).toEqual(["none", "crit", "high", "quiet", "urgent"]);
    expect(
      sortApplications(applications, APPLICATION_SORT.FINDINGS).map(
        (a) => a.id,
      ),
    ).toEqual(["quiet", "high", "crit", "urgent", "none"]);
  });

  it("does not mutate the input", () => {
    const before = applications.map((a) => a.id);
    sortApplications(applications, APPLICATION_SORT.NAME);
    expect(applications.map((a) => a.id)).toEqual(before);
  });
});

describe("paginate", () => {
  const items = Array.from({ length: 60 }, (_, index) => index);

  it("slices pages of 25", () => {
    expect(paginate(items, 1).items).toHaveLength(25);
    expect(paginate(items, 3)).toMatchObject({ page: 3, pages: 3, total: 60 });
    expect(paginate(items, 3).items).toEqual(items.slice(50));
  });

  it("clamps out-of-range pages", () => {
    expect(paginate(items, 9).page).toBe(3);
    expect(paginate([], 4)).toMatchObject({ page: 1, pages: 1, items: [] });
  });
});

describe("query and links", () => {
  it("parses the inventory query with defaults", () => {
    expect(parseApplicationsQuery({})).toEqual({
      q: undefined,
      sort: "risk",
      page: 1,
    });
    expect(
      parseApplicationsQuery({ q: " shop ", sort: "name", page: "2" }),
    ).toEqual({ q: "shop", sort: "name", page: 2 });
    expect(getApplicationSort("bogus")).toBe("risk");
  });

  it("builds inventory links without defaults", () => {
    expect(applicationsHref()).toBe("/application-security/applications");
    expect(applicationsHref({ q: "shop", sort: "risk", page: 1 })).toBe(
      "/application-security/applications?q=shop",
    );
    expect(applicationsHref({ sort: "findings", page: 3 })).toBe(
      "/application-security/applications?sort=findings&page=3",
    );
  });

  it("builds detail links and reads the tab", () => {
    expect(applicationHref("p1")).toBe("/application-security/applications/p1");
    expect(applicationHref("p1", APPLICATION_TAB.SCANS)).toBe(
      "/application-security/applications/p1?tab=scans",
    );
    expect(getApplicationTab("findings")).toBe("findings");
    expect(getApplicationTab(["targets"])).toBe("targets");
    expect(getApplicationTab("nope")).toBe("overview");
  });
});
