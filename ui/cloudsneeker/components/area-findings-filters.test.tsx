import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { parseAreaFilters } from "@/cloudsneeker/lib/area-findings";

import { AreaFindingsFilters } from "./area-findings-filters";

const facets = {
  accounts: [{ id: "prov-1", name: "Production" }],
  regions: ["eu-west-1", "us-east-1"],
  resource_types: ["aws.ebs", "aws.security-group"],
};

describe("AreaFindingsFilters", () => {
  it("offers account, region and resource type from the facets", () => {
    render(
      <AreaFindingsFilters
        area="governance"
        filters={parseAreaFilters({ region: "us-east-1" })}
        sources={[]}
        sourceLabel="Policy"
        facets={facets}
      />,
    );
    expect(
      screen.getByRole("option", { name: "Production" }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Region")).toHaveValue("us-east-1");
    expect(
      screen.getByRole("option", { name: "aws.security-group" }),
    ).toBeInTheDocument();
  });

  it("toggles muted findings", () => {
    render(
      <AreaFindingsFilters
        area="governance"
        filters={parseAreaFilters({})}
        sources={[]}
        sourceLabel="Policy"
      />,
    );
    expect(screen.getByRole("link", { name: "Show muted" })).toHaveAttribute(
      "href",
      "/governance/findings?muted=1",
    );
    expect(screen.queryByLabelText("Region")).toBeNull();
  });
});
