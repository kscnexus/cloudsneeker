import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { BRAND } from "@/cloudsneeker/brand";

import { ThreatScoreLogo } from "./threatscore-logo";

describe("ThreatScoreLogo", () => {
  it("uses the product identity instead of upstream artwork", () => {
    render(<ThreatScoreLogo />);

    expect(
      screen.getByRole("img", {
        name: `${BRAND.name} ThreatScore`,
      }),
    ).toBeVisible();
    expect(screen.queryByText("Prowler")).not.toBeInTheDocument();
  });
});
