import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { AlertStatusBadge, alertStatusLabel } from "./alert-status-badge";

describe("AlertStatusBadge", () => {
  it("keeps the upstream Enabled and Disabled labels", () => {
    expect(alertStatusLabel(true)).toBe("Enabled");
    expect(alertStatusLabel(false)).toBe("Disabled");
  });

  it("renders an enabled rule as a success pill", () => {
    render(<AlertStatusBadge enabled />);

    const badge = screen.getByText("Enabled");
    expect(badge).toHaveAttribute("data-slot", "alert-status-badge");
    expect(badge).toHaveAttribute("data-enabled", "true");
    expect(badge).toHaveClass("text-text-success-primary");
  });

  it("renders a disabled rule as a neutral pill", () => {
    render(<AlertStatusBadge enabled={false} />);

    const badge = screen.getByText("Disabled");
    expect(badge).toHaveAttribute("data-enabled", "false");
    expect(badge).toHaveClass("bg-bg-tag");
  });
});
