import { describe, expect, it } from "vitest";

import { areaFindingHref } from "@/cloudsneeker/lib/area-findings";

import {
  SEARCH_GROUP,
  searchHitHref,
  searchMoreHref,
  searchQueryOf,
  searchTotal,
  toSearchGroups,
} from "./global-search";

describe("searchQueryOf", () => {
  it("trims and collapses the query", () => {
    expect(searchQueryOf({ q: "  prod   bucket " })).toBe("prod bucket");
  });

  it("is empty for a missing or one-character query", () => {
    expect(searchQueryOf({})).toBe("");
    expect(searchQueryOf({ q: "a" })).toBe("");
  });
});

describe("search links", () => {
  it("opens findings on their own detail or list page", () => {
    expect(
      searchHitHref(SEARCH_GROUP.APPLICATION_FINDINGS, { id: "trivy-1" }),
    ).toBe("/application-security/findings/trivy-1");
    expect(
      searchHitHref(SEARCH_GROUP.GOVERNANCE_FINDINGS, { id: "custodian-p-1" }),
    ).toBe(
      areaFindingHref("governance", { uid: "custodian-p-1", checkId: "" }),
    );
    expect(
      searchHitHref(SEARCH_GROUP.CLOUD_FINDINGS, {
        id: "u",
        check_id: "s3_public",
      }),
    ).toBe("/findings?filter%5Bcheck_id__in%5D=s3_public");
  });

  it("opens other hits on their pages", () => {
    expect(searchHitHref(SEARCH_GROUP.POLICIES, { id: "p1" })).toBe(
      "/governance/p1",
    );
    expect(searchHitHref(SEARCH_GROUP.TARGETS, { id: "t1" })).toBe(
      "/application-security/t1",
    );
    expect(searchHitHref(SEARCH_GROUP.ALERT_RULES, { id: "r1" })).toBe(
      "/alerts?edit=r1",
    );
    expect(
      searchHitHref(SEARCH_GROUP.ACCOUNTS, { id: "x", uid: "123456789012" }),
    ).toBe("/providers?filter%5Bsearch%5D=123456789012");
  });

  it("links each group to its filtered list", () => {
    expect(searchMoreHref(SEARCH_GROUP.GOVERNANCE_FINDINGS, "bucket")).toBe(
      "/governance/findings?q=bucket",
    );
    expect(searchMoreHref(SEARCH_GROUP.POLICIES, "bucket")).toBe(
      "/governance?tab=policies&q=bucket",
    );
  });
});

describe("toSearchGroups", () => {
  it("keeps known groups and well-formed hits", () => {
    const groups = toSearchGroups(
      {
        data: [
          {
            id: "governance_policies",
            attributes: {
              count: 2,
              hits: [{ id: "p1", title: "Public buckets" }, { title: "x" }],
            },
          },
          { id: "unknown_group", attributes: { count: 3, hits: [] } },
        ],
      },
      "bucket",
    );
    expect(groups).toHaveLength(1);
    expect(groups[0]).toMatchObject({
      kind: "governance_policies",
      label: "Cloud Governance policies",
      count: 2,
      moreHref: "/governance?tab=policies&q=bucket",
    });
    expect(groups[0].hits.map((hit) => hit.href)).toEqual(["/governance/p1"]);
    expect(searchTotal(groups)).toBe(2);
  });

  it("returns nothing for an error", () => {
    expect(toSearchGroups({ error: "x" }, "q")).toEqual([]);
  });
});
