import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SectionCard } from "./section-card";

describe("SectionCard", () => {
  it("is a labelled region with a heading, description and actions", () => {
    render(
      <SectionCard
        title="Recent scans"
        description="Newest first."
        actions={<a href="/all">View all</a>}
      >
        <p>Body</p>
      </SectionCard>,
    );

    const region = screen.getByRole("region", { name: "Recent scans" });
    expect(
      within(region).getByRole("heading", { level: 2, name: "Recent scans" }),
    ).toBeInTheDocument();
    expect(within(region).getByText("Newest first.")).toBeInTheDocument();
    expect(within(region).getByRole("link", { name: "View all" })).toBeInTheDocument();
    expect(within(region).getByText("Body")).toBeInTheDocument();
  });
});
