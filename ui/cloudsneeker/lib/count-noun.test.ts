import { describe, expect, it } from "vitest";

import { countNoun } from "./count-noun";

describe("countNoun", () => {
  it("uses the singular only for one", () => {
    expect(countNoun(1, "finding")).toBe("1 finding");
    expect(countNoun(0, "finding")).toBe("0 findings");
    expect(countNoun(1200, "source")).toBe("1,200 sources");
    expect(countNoun(2, "time", "times")).toBe("2 times");
  });
});
