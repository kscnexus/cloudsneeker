import { describe, expect, it } from "vitest";

import {
  filterInMemory,
  hasListFilters,
  listHref,
  pageOf,
  paginationOf,
  parseListFilters,
  POLICY_SCHEDULE,
  policyListQuery,
  runListQuery,
} from "./list-filters";

describe("parseListFilters", () => {
  it("reads search, selects and a valid page", () => {
    expect(
      parseListFilters({
        q: " ebs ",
        provider: "p1",
        status: "failed",
        page: "3",
      }),
    ).toEqual({
      search: "ebs",
      provider: "p1",
      status: "failed",
      type: "",
      page: 3,
    });
    expect(parseListFilters({ page: "-2" }).page).toBe(1);
    expect(
      parseListFilters({
        "filter[search]": "s3",
        "filter[provider]": "p2",
        q: "ignored",
      }),
    ).toMatchObject({ search: "s3", provider: "p2" });
    expect(hasListFilters(parseListFilters({}))).toBe(false);
  });
});

describe("links and queries", () => {
  it("keeps the tab and drops page 1", () => {
    expect(
      listHref("/governance", { tab: "policies" }, { search: "s3", page: 1 }),
    ).toBe("/governance?tab=policies&filter%5Bsearch%5D=s3");
    expect(listHref("/x", {}, { page: 2 })).toBe("/x?page=2");
  });

  it("sends server-side filters", () => {
    const filters = parseListFilters({
      q: "a",
      provider: "p",
      status: "failed",
    });
    expect(policyListQuery(filters)).toMatchObject({
      "filter[search]": "a",
      "filter[provider]": "p",
      "page[number]": "1",
    });
    expect(runListQuery(filters)["filter[status]"]).toBe("failed");
  });

  it("reads pagination and clamps the page", () => {
    expect(
      paginationOf({ meta: { pagination: { pages: 2, count: 30 } } }, 9),
    ).toEqual({ page: 2, pages: 2, count: 30 });
    expect(paginationOf(undefined, 1)).toEqual({ page: 1, pages: 1, count: 0 });
  });
});

describe("in-memory lists", () => {
  const items = Array.from({ length: 30 }, (_, index) => ({
    name: `target-${index}`,
    mode: index % 2 ? "repo" : "image",
  }));

  it("filters by text and type", () => {
    const result = filterInMemory(
      items,
      parseListFilters({ q: "target-1", type: "repo" }),
      { text: (item) => [item.name], type: (item) => item.mode },
    );
    expect(result.every((item) => item.mode === "repo")).toBe(true);
    expect(result.every((item) => item.name.includes("target-1"))).toBe(true);
  });

  it("pages and clamps", () => {
    expect(pageOf(items, 2).rows).toHaveLength(5);
    expect(pageOf(items, 99).pagination).toEqual({
      page: 2,
      pages: 2,
      count: 30,
    });
    expect(pageOf([], 1).pagination.pages).toBe(1);
  });
});

describe("policy schedule filter", () => {
  it("maps the schedule select to filter[schedule_enabled]", () => {
    expect(
      policyListQuery(parseListFilters({ type: POLICY_SCHEDULE.ON }))[
        "filter[schedule_enabled]"
      ],
    ).toBe("true");
    expect(
      policyListQuery(parseListFilters({ type: POLICY_SCHEDULE.OFF }))[
        "filter[schedule_enabled]"
      ],
    ).toBe("false");
    expect(policyListQuery(parseListFilters({}))).not.toHaveProperty(
      "filter[schedule_enabled]",
    );
  });
});
