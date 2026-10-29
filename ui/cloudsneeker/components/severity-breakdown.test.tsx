import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SeverityBreakdown } from "./severity-breakdown";

describe("SeverityBreakdown", () => {
  it("summarises counts and links each severity", () => {
    render(
      <SeverityBreakdown
        items={[
          { severity: "critical", count: 3, href: "/findings?sev=critical" },
          { severity: "high", count: 1 },
        ]}
      />,
    );

    expect(
      screen.getByRole("img", {
        name: "Open findings by severity: Critical 3, High 1",
      }),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Critical\s*3/ })).toHaveAttribute(
      "href",
      "/findings?sev=critical",
    );
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(screen.getAllByRole("link")).toHaveLength(1);
  });

  it("says none when every count is zero", () => {
    render(<SeverityBreakdown items={[{ severity: "low", count: 0 }]} />);

    expect(
      screen.getByRole("img", { name: "Open findings by severity: none" }),
    ).toBeInTheDocument();
  });
});
