import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { BrandMark, BrandWordmark, BrandWordmarkSvg } from "./brand-logo";

describe("BrandMark", () => {
  it("is decorative by default", () => {
    // When
    const { container } = render(<BrandMark size={20} />);

    // Then
    expect(container.querySelector("svg")).toHaveAttribute(
      "aria-hidden",
      "true",
    );
    expect(screen.queryByRole("img")).toBeNull();
  });

  it("becomes an accessible image when the caller names it", () => {
    // When
    render(<BrandMark aria-label="Owner" role="img" size={20} />);

    // Then
    const image = screen.getByRole("img", { name: "Owner" });
    expect(image).not.toHaveAttribute("aria-hidden");
  });
});

describe("wordmarks", () => {
  it("expose the product name as the accessible name", () => {
    // When
    render(
      <>
        <BrandWordmark />
        <BrandWordmarkSvg />
      </>,
    );

    // Then
    expect(screen.getAllByRole("img", { name: "Cloudsneeker" })).toHaveLength(
      2,
    );
  });
});
