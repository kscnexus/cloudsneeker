import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ProwlerBrand } from "./ProwlerIcons";

describe("ProwlerBrand", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllEnvs();
  });

  it("renders the Cloudsneeker wordmark", () => {
    // When
    render(<ProwlerBrand />);

    // Then
    expect(screen.getByRole("img", { name: "Cloudsneeker" })).toHaveTextContent(
      "Cloudsneeker",
    );
  });

  it("keeps the Cloudsneeker wordmark when cloud mode is enabled", () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");

    // When
    render(<ProwlerBrand />);

    // Then
    expect(screen.getByRole("img", { name: "Cloudsneeker" })).toHaveTextContent(
      "Cloudsneeker",
    );
  });
});
