import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { EmptyState } from "./empty-state";

describe("EmptyState", () => {
  it("renders the title, description and call to action", () => {
    render(
      <EmptyState
        icon={<svg data-testid="icon" />}
        title="No targets yet"
        description="Add a target to start scanning."
        action={<a href="/application-security/new">Create a target</a>}
      />,
    );

    expect(
      screen.getByRole("heading", { level: 3, name: "No targets yet" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Add a target to start scanning."),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Create a target" })).toHaveAttribute(
      "href",
      "/application-security/new",
    );
    expect(screen.getByTestId("icon").parentElement).toHaveAttribute(
      "aria-hidden",
      "true",
    );
  });
});
