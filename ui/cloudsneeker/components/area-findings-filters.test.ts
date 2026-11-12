import { describe, expect, it } from "vitest";

import { buildAreaFilters } from "./area-findings-filters";

describe("buildAreaFilters", () => {
  it("offers severity, status, source and muted; facets only when present", () => {
    const filters = buildAreaFilters({
      sources: [{ id: "p1", name: "Public buckets", kind: "policy" }],
      sourceLabel: "Policies",
    });
    expect(filters.map((filter) => filter.label)).toEqual([
      "Severities",
      "Statuses",
      "Policies",
      "Findings (muted hidden)",
    ]);
    expect(filters[2].options).toEqual([
      { value: "p1", label: "Public buckets" },
    ]);
  });

  it("adds account, region and resource type facets", () => {
    const filters = buildAreaFilters({
      sources: [],
      sourceLabel: "Policies",
      facets: {
        accounts: [{ id: "a1", name: "466920982015" }],
        regions: ["us-east-1"],
        resource_types: ["aws.s3"],
      },
    });
    expect(filters.map((filter) => filter.key)).toEqual([
      "filter[severity__in]",
      "filter[triage_status__in]",
      "filter[source__in]",
      "filter[provider__in]",
      "filter[region__in]",
      "filter[resource_type__in]",
      "filter[muted]",
    ]);
  });
});
