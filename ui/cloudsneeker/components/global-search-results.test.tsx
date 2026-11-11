import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { SearchGroupItem } from "@/cloudsneeker/lib/global-search";

import { GlobalSearchResults } from "./global-search-results";

const group = (overrides: Partial<SearchGroupItem>): SearchGroupItem => ({
  kind: "governance_policies",
  label: "Cloud Governance policies",
  count: 1,
  moreHref: "/governance?tab=policies&q=bucket",
  hits: [
    {
      id: "p1",
      title: "Public buckets",
      subtitle: "Buckets with public access",
      href: "/governance/p1",
      severity: "",
    },
  ],
  ...overrides,
});

describe("GlobalSearchResults", () => {
  it("lists groups with matches and links each hit", () => {
    render(
      <GlobalSearchResults
        query="bucket"
        groups={[
          group({ count: 7 }),
          group({
            kind: "alert_rules",
            label: "Alert rules",
            count: 0,
            hits: [],
          }),
        ]}
        loadError={null}
      />,
    );
    expect(
      screen.getByRole("link", { name: "Public buckets" }),
    ).toHaveAttribute("href", "/governance/p1");
    expect(screen.getByRole("link", { name: "See all 7" })).toHaveAttribute(
      "href",
      "/governance?tab=policies&q=bucket",
    );
    expect(screen.getByText("No matches in: Alert rules.")).toBeInTheDocument();
  });

  it("says when nothing matches", () => {
    render(
      <GlobalSearchResults
        query="zzz"
        groups={[group({ count: 0, hits: [] })]}
        loadError={null}
      />,
    );
    expect(screen.getByText("Nothing matches “zzz”")).toBeInTheDocument();
  });

  it("explains a failed search", () => {
    render(
      <GlobalSearchResults query="x" groups={[]} loadError="Server error" />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Search failed. Server error",
    );
  });
});
