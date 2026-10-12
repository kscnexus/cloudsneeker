import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { docsUrl } from "@/cloudsneeker/brand"; // cloudsneeker-hook

import { CrossProviderHubLink } from "./cross-provider-hub-link";

describe("CrossProviderHubLink", () => {
  it("opens the framework page in the documentation safely", () => {
    // Given / When
    render(<CrossProviderHubLink complianceId="cis_controls_8.1" />);

    // Then
    const link = screen.getByRole("link", { name: /view documentation/i });
    expect(link).toHaveAttribute(
      "href",
      docsUrl("compliance/cis_controls_8.1"),
    );
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });
});
