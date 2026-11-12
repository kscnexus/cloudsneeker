import { describe, expect, it } from "vitest";

import { PAGE_GAP, pageWindow } from "./page-window";

describe("pageWindow", () => {
  it("shows every page when there are few", () => {
    expect(pageWindow(1, 1)).toEqual([1]);
    expect(pageWindow(2, 4)).toEqual([1, 2, 3, 4]);
    expect(pageWindow(1, 0)).toEqual([]);
  });

  it("keeps first, last and the pages around the current one", () => {
    expect(pageWindow(5, 16)).toEqual([1, PAGE_GAP, 4, 5, 6, PAGE_GAP, 16]);
    expect(pageWindow(1, 16)).toEqual([1, 2, PAGE_GAP, 16]);
    expect(pageWindow(16, 16)).toEqual([1, PAGE_GAP, 15, 16]);
  });

  it("shows a single hidden page instead of a gap", () => {
    expect(pageWindow(4, 16)).toEqual([1, 2, 3, 4, 5, PAGE_GAP, 16]);
  });

  it("clamps an out-of-range page", () => {
    expect(pageWindow(99, 5)).toEqual([1, 2, 3, 4, 5]);
  });
});
