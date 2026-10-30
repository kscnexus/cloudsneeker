import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FindingTriageStatusFilter } from "./finding-triage-status-filter";

describe("FindingTriageStatusFilter", () => {
  it("links every status and marks the active one", () => {
    render(<FindingTriageStatusFilter active="resolved" />);

    expect(
      screen.getByRole("navigation", { name: "Triage status" }),
    ).toBeInTheDocument();
    const all = screen.getByRole("link", { name: "All" });
    expect(all).toHaveAttribute("href", "/triage");
    expect(all).not.toHaveAttribute("aria-current");
    const resolved = screen.getByRole("link", { name: "Resolved" });
    expect(resolved).toHaveAttribute("href", "/triage?status=resolved");
    expect(resolved).toHaveAttribute("aria-current", "page");
    expect(
      screen.getByRole("link", { name: "False Positive" }),
    ).toHaveAttribute("href", "/triage?status=false_positive");
  });

  it("marks All active without a status", () => {
    render(<FindingTriageStatusFilter active={null} />);

    expect(screen.getByRole("link", { name: "All" })).toHaveAttribute(
      "aria-current",
      "page",
    );
  });
});
