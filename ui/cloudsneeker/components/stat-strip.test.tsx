import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { StatStrip } from "./stat-strip";

describe("StatStrip", () => {
  it("renders each stat with its label and value", () => {
    render(
      <StatStrip
        label="Vulnerability detail"
        items={[
          { label: "Instances", value: 12 },
          { label: "Unique advisories", value: 7 },
        ]}
      />,
    );

    const list = screen.getByRole("list", { name: "Vulnerability detail" });
    expect(list).toBeInTheDocument();
    expect(screen.getAllByRole("listitem")).toHaveLength(2);
    expect(screen.getByText("Instances")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
  });

  it("links a stat that drills down and names the link by label and value", () => {
    render(
      <StatStrip
        label="Vulnerability detail"
        items={[
          { label: "Fix available", value: 4, href: "/findings?fix=available" },
          { label: "Affected packages", value: 9 },
        ]}
      />,
    );

    const link = screen.getByRole("link", { name: "Fix available: 4" });
    expect(link).toHaveAttribute("href", "/findings?fix=available");
    expect(screen.getAllByRole("link")).toHaveLength(1);
  });

  it("keeps a hint readable for assistive technology", () => {
    render(
      <StatStrip
        label="Vulnerability detail"
        items={[
          {
            label: "Instances",
            value: 3,
            hint: "Vulnerability, package and location",
          },
        ]}
      />,
    );

    expect(
      screen.getByText("Vulnerability, package and location"),
    ).toBeInTheDocument();
  });
});
