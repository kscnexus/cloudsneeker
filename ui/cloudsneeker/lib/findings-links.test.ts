import { describe, expect, it } from "vitest";

import { openFindingsHref, responseCount, responseList } from "./findings-links";

describe("openFindingsHref", () => {
  it("filters to failed, unmuted findings plus extra filters", () => {
    const href = openFindingsHref({
      "filter[severity__in]": "high",
      "filter[scan__in]": "",
    });
    const [path, query] = href.split("?");
    const params = new URLSearchParams(query);

    expect(path).toBe("/findings");
    expect(params.get("filter[status__in]")).toBe("FAIL");
    expect(params.get("filter[muted]")).toBe("false");
    expect(params.get("filter[severity__in]")).toBe("high");
    expect(params.has("filter[scan__in]")).toBe(false);
  });
});

describe("responseList", () => {
  it("returns data arrays and an empty list otherwise", () => {
    expect(responseList<number>({ data: [1, 2] })).toEqual([1, 2]);
    expect(responseList({ data: { id: "x" } })).toEqual([]);
    expect(responseList({ error: "boom" })).toEqual([]);
    expect(responseList(undefined)).toEqual([]);
  });
});

describe("responseCount", () => {
  it("reads meta.pagination.count", () => {
    expect(responseCount({ meta: { pagination: { count: 12 } } })).toBe(12);
    expect(responseCount({ meta: {} })).toBeNull();
    expect(responseCount({ error: "boom" })).toBeNull();
    expect(responseCount(null)).toBeNull();
  });
});
