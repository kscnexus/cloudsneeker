import { describe, expect, it } from "vitest";

import {
  MATCHING_PAGES,
  matchingPageQuery,
  matchingSelectionSize,
  selectionLabel,
} from "./matching-selection";

describe("matching selection", () => {
  it("pages through the same filters 100 at a time", () => {
    expect(
      matchingPageQuery({ "filter[area]": "cloud", "page[number]": "3" }, 2),
    ).toEqual({
      "filter[area]": "cloud",
      "page[number]": "2",
      "page[size]": "100",
    });
    expect(MATCHING_PAGES).toBe(5);
  });

  it("caps the selection at 500", () => {
    expect(matchingSelectionSize(42)).toBe(42);
    expect(matchingSelectionSize(9000)).toBe(500);
    expect(matchingSelectionSize(-1)).toBe(0);
  });

  it("says when the selection reaches beyond the page", () => {
    expect(selectionLabel(3, 25)).toBe("3 selected on this page");
    expect(selectionLabel(120, 25)).toBe("120 selected across pages");
  });
});
