import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { PageHeader } from "./page-header";

describe("PageHeader", () => {
  it("renders the description, record facts and actions", () => {
    render(
      <PageHeader
        title="Workspace"
        description="Scan everything."
        meta={[
          { label: "Mode", value: "SBOM" },
          { label: "Schedule", value: "Off" },
        ]}
        actions={<button type="button">New target</button>}
      />,
    );

    expect(
      screen.getByRole("heading", { level: 2, name: "Workspace" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Scan everything.")).toBeInTheDocument();
    expect(screen.getByText("Mode")).toBeInTheDocument();
    expect(screen.getByText("SBOM")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "New target" }),
    ).toBeInTheDocument();
  });

  it("omits empty parts", () => {
    const { container } = render(<PageHeader description="Only text." />);

    expect(screen.queryByRole("heading")).not.toBeInTheDocument();
    expect(container.querySelector("dl")).toBeNull();
  });
});
