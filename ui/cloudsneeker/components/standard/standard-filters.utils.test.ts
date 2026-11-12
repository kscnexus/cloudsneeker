import { describe, expect, it } from "vitest";

import { FILTER_SELECTION_MODE } from "@/types/filters";

import { buildStandardChips, toFilterOption } from "./standard-filters.utils";

const SEVERITY = {
  key: "filter[severity__in]",
  label: "Severities",
  options: [
    { value: "critical", label: "Critical" },
    { value: "high", label: "High" },
  ],
};

describe("toFilterOption", () => {
  it("maps plain options to the upstream dropdown with labels", () => {
    const option = toFilterOption(SEVERITY);
    expect(option.values).toEqual(["critical", "high"]);
    expect(option.labelFormatter?.("high")).toBe("High");
    expect(option.labelFormatter?.("other")).toBe("other");
    expect(option.selectionMode).toBe(FILTER_SELECTION_MODE.MULTIPLE);
    expect(
      toFilterOption({ ...SEVERITY, single: true, wide: true }),
    ).toMatchObject({
      selectionMode: FILTER_SELECTION_MODE.SINGLE,
      width: "wide",
    });
  });
});

describe("buildStandardChips", () => {
  it("makes one labelled chip per value and skips unknown keys", () => {
    expect(
      buildStandardChips(
        {
          "filter[severity__in]": ["critical", "low"],
          "filter[other]": ["x"],
        },
        [SEVERITY],
      ),
    ).toEqual([
      {
        key: "filter[severity__in]",
        label: "Severities",
        value: "critical",
        displayValue: "Critical",
      },
      {
        key: "filter[severity__in]",
        label: "Severities",
        value: "low",
        displayValue: "low",
      },
    ]);
  });

  it("matches bare field names to filter keys", () => {
    expect(
      buildStandardChips({ "filter[state__in]": ["open"] }, [
        { key: "state__in", label: "States", options: [] },
      ]),
    ).toHaveLength(1);
  });
});
