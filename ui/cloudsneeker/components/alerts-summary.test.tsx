import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AlertsSummary } from "./alerts-summary";

const tile = (label: string) =>
  screen.getByText(label).closest("[data-slot='stat-tile']") as HTMLElement;

describe("AlertsSummary", () => {
  it("shows totals, active, paused and destinations", () => {
    render(
      <AlertsSummary
        alerts={[
          {
            attributes: {
              enabled: true,
              recipient_emails: ["secops@example.com"],
              slack_channels: [{ id: "C1" }],
            },
          },
          { attributes: { enabled: false } },
        ]}
        totalCount={2}
      />,
    );

    expect(
      screen.getByRole("list", { name: "Alert figures" }),
    ).toBeInTheDocument();
    expect(within(tile("Alert rules")).getByText("2")).toBeInTheDocument();
    expect(within(tile("Active")).getByText("1")).toBeInTheDocument();
    expect(within(tile("Paused")).getByText("1")).toBeInTheDocument();
    expect(within(tile("Destinations")).getByText("2")).toBeInTheDocument();
    expect(screen.queryByText("Rules on this page")).not.toBeInTheDocument();
  });

  it("says the counts cover this page when more rules exist", () => {
    render(
      <AlertsSummary
        alerts={[{ attributes: { enabled: true } }]}
        totalCount={40}
      />,
    );

    expect(within(tile("Alert rules")).getByText("40")).toBeInTheDocument();
    expect(screen.getAllByText("Rules on this page")).toHaveLength(3);
  });

  it("marks the page as the alerts surface for the scoped styles", () => {
    render(<AlertsSummary alerts={[]} totalCount={0} />);

    expect(screen.getByRole("list", { name: "Alert figures" })).toHaveAttribute(
      "data-cloudsneeker-surface",
      "alerts",
    );
  });

  it("renders only a hidden surface marker when the list failed to load", () => {
    const { container } = render(<AlertsSummary alerts={[]} unavailable />);

    expect(screen.queryByRole("list")).not.toBeInTheDocument();
    const marker = container.querySelector(
      '[data-cloudsneeker-surface="alerts"]',
    );
    expect(marker).toHaveAttribute("hidden");
    expect(marker).toBeEmptyDOMElement();
  });
});
