import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  formatProfileDate,
  ScanProfilesSummary,
} from "./scan-profiles-summary";

const tile = (label: string) =>
  screen.getByText(label).closest("[data-slot='stat-tile']") as HTMLElement;

describe("ScanProfilesSummary", () => {
  it("shows profiles, covered providers, defaults and the last edit", () => {
    render(
      <ScanProfilesSummary
        profiles={[
          {
            attributes: {
              providers: ["p1"],
              updated_at: "2026-10-20T08:30:00Z",
            },
          },
        ]}
        providerIds={["p1", "p2", "p3"]}
      />,
    );

    expect(
      screen.getByRole("list", { name: "Scan profile figures" }),
    ).toBeInTheDocument();
    expect(within(tile("Scan profiles")).getByText("1")).toBeInTheDocument();
    expect(
      within(tile("Providers with a profile")).getByText("1"),
    ).toBeInTheDocument();
    expect(screen.getByText("Of 3 connected")).toBeInTheDocument();
    expect(within(tile("Using defaults")).getByText("2")).toBeInTheDocument();
    expect(
      within(tile("Last edited")).getByText("Oct 20, 2026"),
    ).toBeInTheDocument();
  });
});

describe("formatProfileDate", () => {
  it("formats in UTC and falls back to a dash", () => {
    expect(formatProfileDate("2026-01-02T23:59:00Z")).toBe("Jan 2, 2026");
    expect(formatProfileDate(null)).toBe("—");
    expect(formatProfileDate("not a date")).toBe("—");
  });
});
