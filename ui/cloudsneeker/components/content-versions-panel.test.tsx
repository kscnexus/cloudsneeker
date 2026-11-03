import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { ContentVersionsAttributes } from "@/cloudsneeker/types/content-versions";

import {
  ContentVersionsPanel,
  formatAge,
  formatUtc,
} from "./content-versions-panel";

const versions: ContentVersionsAttributes = {
  release: "0f4e7f5252bc",
  cloud_security: { version: "5.45.0", checks: 1616, frameworks: 105 },
  vulnerability_database: {
    status: "fresh",
    refreshed_at: "2026-11-04T06:00:12Z",
    published_at: "2026-11-04T00:31:40Z",
    age_hours: 2.4,
    max_age_hours: 24,
    java_db: true,
  },
  code_analysis_rules: { version: "v2.10.1", rules: 412 },
  engines: [
    {
      id: "scanner",
      label: "Vulnerability and IaC scanner",
      version: "0.74.0",
    },
    { id: "code_analyzer", label: "Code analyzer", version: null },
  ],
};

describe("ContentVersionsPanel", () => {
  it("lists content and engine versions", () => {
    render(<ContentVersionsPanel versions={versions} />);
    expect(screen.getByText("Release 5.45.0")).toBeInTheDocument();
    expect(
      screen.getByText("1,616 checks, 105 compliance frameworks"),
    ).toBeInTheDocument();
    expect(screen.getByText("Current")).toBeInTheDocument();
    expect(
      screen.getByText(/Refreshed 2026-11-04 06:00 UTC/),
    ).toBeInTheDocument();
    expect(screen.getByText("Release v2.10.1")).toBeInTheDocument();
    expect(screen.getByText("0.74.0")).toBeInTheDocument();
    expect(screen.getByText("Not available")).toBeInTheDocument();
    expect(
      screen.getByText(/platform release 0f4e7f5252bc/),
    ).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("warns when the vulnerability database is older than the limit", () => {
    render(
      <ContentVersionsPanel
        versions={{
          ...versions,
          vulnerability_database: {
            ...versions.vulnerability_database,
            status: "stale",
            age_hours: 30,
          },
        }}
      />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      "last refreshed 30 hours ago, more than the 24-hour limit",
    );
    expect(screen.getByText("Out of date")).toBeInTheDocument();
  });

  it("warns when no snapshot was downloaded", () => {
    render(
      <ContentVersionsPanel
        versions={{
          ...versions,
          vulnerability_database: {
            ...versions.vulnerability_database,
            status: "missing",
            refreshed_at: null,
            published_at: null,
            age_hours: null,
          },
        }}
      />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      "not been downloaded yet",
    );
  });

  it("does not warn when the deployment has no shared cache", () => {
    render(
      <ContentVersionsPanel
        versions={{
          ...versions,
          vulnerability_database: {
            ...versions.vulnerability_database,
            status: "not_configured",
            refreshed_at: null,
            age_hours: null,
          },
        }}
      />,
    );
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByText("Downloaded by each scan")).toBeInTheDocument();
  });
});

describe("formatters", () => {
  it("formats ages and times", () => {
    expect(formatAge(0.2)).toBe("Less than an hour");
    expect(formatAge(72)).toBe("3 days");
    expect(formatUtc(null)).toBe("Not available");
    expect(formatUtc("bad")).toBe("Not available");
  });
});
