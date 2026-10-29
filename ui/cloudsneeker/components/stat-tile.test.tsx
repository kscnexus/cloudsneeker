import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { STAT_TILE_TONE, StatTile } from "./stat-tile";

describe("StatTile", () => {
  it("renders label, value and hint without a link", () => {
    render(<StatTile label="Targets" value={4} hint="2 on a schedule" />);

    expect(screen.getByText("Targets")).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();
    expect(screen.getByText("2 on a schedule")).toBeInTheDocument();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });

  it("becomes a focusable link and marks the selected filter", () => {
    render(
      <StatTile
        label="Secrets"
        value={2}
        href="/application-security?category=secrets"
        tone={STAT_TILE_TONE.CRITICAL}
        selected
      />,
    );

    const link = screen.getByRole("link", { name: /Secrets/ });
    expect(link).toHaveAttribute("href", "/application-security?category=secrets");
    expect(link).toHaveAttribute("aria-current", "true");
    expect(link.className).toContain("focus-visible:ring-2");
    expect(link.querySelector('[data-tone="critical"]')).not.toBeNull();
  });
});
