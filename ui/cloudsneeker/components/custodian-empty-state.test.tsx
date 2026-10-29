import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { CustodianEmptyState } from "./custodian-empty-state";

describe("CustodianEmptyState", () => {
  it("explains dry-run only and links to create", () => {
    render(<CustodianEmptyState />);

    expect(
      screen.getByText(/No governance policies yet/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/AWS, Azure, GCP, or Kubernetes/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/Apply mode is not available/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Create policy/i })).toHaveAttribute(
      "href",
      "/governance/new",
    );
  });
});
