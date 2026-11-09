import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { SkipToContent } from "./skip-to-content";

describe("SkipToContent", () => {
  afterEach(() => {
    document.body.innerHTML = "";
  });

  it("renders a named link", () => {
    render(<SkipToContent />);

    expect(
      screen.getByRole("link", { name: "Skip to content" }),
    ).toBeInTheDocument();
  });

  it("moves focus to the page region of the shell", () => {
    const main = document.createElement("main");
    main.setAttribute("data-responsive-container", "");
    document.body.appendChild(main);
    render(<SkipToContent />);

    fireEvent.click(screen.getByRole("link", { name: "Skip to content" }));

    expect(main).toHaveAttribute("tabindex", "-1");
    expect(document.activeElement).toBe(main);
  });

  it("keeps an existing tabindex on the page region", () => {
    const main = document.createElement("main");
    main.setAttribute("data-responsive-container", "");
    main.setAttribute("tabindex", "0");
    document.body.appendChild(main);
    render(<SkipToContent />);

    fireEvent.click(screen.getByRole("link", { name: "Skip to content" }));

    expect(main).toHaveAttribute("tabindex", "0");
  });
});
