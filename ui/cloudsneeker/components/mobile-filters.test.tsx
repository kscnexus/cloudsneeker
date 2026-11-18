import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { MobileFilters } from "./mobile-filters";

describe("MobileFilters", () => {
  it("folds the filters behind a toggle on phones", async () => {
    const user = userEvent.setup();
    render(
      <MobileFilters>
        <p>Provider filter</p>
      </MobileFilters>,
    );

    const toggle = screen.getByRole("button", { name: "Filters" });
    const panel = screen.getByText("Provider filter").parentElement!;
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(panel).toHaveClass("hidden", "md:block");

    await user.click(toggle);

    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(panel).toHaveClass("block");
    expect(panel).not.toHaveClass("hidden");
  });
});
