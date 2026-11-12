import { describe, expect, it } from "vitest";

import {
  filterParam,
  readFilterList,
  readFilterValue,
  readPage,
  readPageSize,
  readSearch,
  withListParams,
} from "./standard-list";

describe("standard list parameters", () => {
  it("reads filter[...] lists, falling back to legacy names", () => {
    expect(filterParam("state__in")).toBe("filter[state__in]");
    expect(filterParam("filter[x]")).toBe("filter[x]");
    expect(
      readFilterList({ "filter[state__in]": "open, fixed,open" }, "state__in"),
    ).toEqual(["open", "fixed"]);
    expect(readFilterList({ state: "new" }, "state__in", ["state"])).toEqual([
      "new",
    ]);
    expect(readFilterValue({}, "state__in")).toBe("");
  });

  it("reads search, page and page size", () => {
    expect(readSearch({ "filter[search]": " cve " })).toBe("cve");
    expect(readSearch({ q: "x" }, ["q"])).toBe("x");
    expect(readPage({ page: "3" })).toBe(3);
    expect(readPage({ page: "-1" })).toBe(1);
    expect(readPageSize({ pageSize: "50" }, 25)).toBe(50);
    expect(readPageSize({ pageSize: "999" }, 25)).toBe(100);
    expect(readPageSize({}, 25)).toBe(25);
  });

  it("sets and removes parameters", () => {
    const next = withListParams(new URLSearchParams("page=2&a=1"), {
      page: null,
      "filter[s]": ["x", "y"],
      pageSize: 50,
    });
    expect(next.toString()).toBe("a=1&filter%5Bs%5D=x%2Cy&pageSize=50");
  });
});
