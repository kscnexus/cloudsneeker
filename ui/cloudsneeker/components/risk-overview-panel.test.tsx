import { render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { buildRiskOverview } from "@/cloudsneeker/lib/risk-overview";

import { EXECUTIVE_REPORT_FIXTURE } from "./report-view.fixture";
import { RISK_OVERVIEW_TITLE, RiskOverviewPanel } from "./risk-overview-panel";

// The refresh button calls a server action and the router; the panel only
// decides where it appears.
vi.mock("./risk-overview-refresh-button", () => ({
  RiskOverviewRefreshButton: ({ label }: { label: string }) => (
    <button type="button">{label}</button>
  ),
}));

describe("RiskOverviewPanel", () => {
  it("shows the score, severity totals, areas, top risks and trend", () => {
    render(
      <RiskOverviewPanel
        model={buildRiskOverview(EXECUTIVE_REPORT_FIXTURE, "run-1")}
      />,
    );

    const region = screen.getByRole("region", { name: RISK_OVERVIEW_TITLE });
    expect(
      within(region).getByRole("img", {
        name: /Security score 72 of 100, grade C/,
      }),
    ).toBeInTheDocument();
    expect(within(region).getByText("42")).toBeInTheDocument();
    expect(
      within(region).getByRole("img", { name: /Critical 5, High 37/ }),
    ).toBeInTheDocument();

    const areas = within(region).getByRole("list", { name: "Score by area" });
    expect(within(areas).getAllByRole("link")).toHaveLength(4);
    expect(
      within(areas).getByRole("link", { name: /Application Security/ }),
    ).toHaveAttribute("href", "/application-security");
    expect(
      within(areas).getByRole("link", { name: /Cloud Governance/ }),
    ).toHaveAttribute("href", "/governance");
    expect(within(areas).getAllByText("Not connected yet")).toHaveLength(3);

    expect(
      within(region).getByRole("link", {
        name: /S3 bucket allows public access/,
      }),
    ).toHaveAttribute(
      "href",
      expect.stringContaining("filter%5Bcheck_id__in%5D=s3_bucket_public_access"),
    );
    expect(
      within(region).getByText("8 fewer open issues over this period."),
    ).toBeInTheDocument();
    expect(
      within(region).getByRole("link", { name: "Full report" }),
    ).toHaveAttribute("href", "/reports/run-1");
    expect(
      within(region).getByRole("button", { name: "Refresh" }),
    ).toBeInTheDocument();
  });

  it("offers to build the risk view when no report exists", () => {
    render(<RiskOverviewPanel model={null} />);

    expect(
      screen.getByRole("heading", { name: "No risk score yet" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Build risk view" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open reports" })).toHaveAttribute(
      "href",
      "/reports",
    );
  });

  it("hides the refresh control while a newer report is prepared", () => {
    render(<RiskOverviewPanel model={null} refreshing />);

    expect(screen.getByRole("status")).toHaveTextContent(/Updating/);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
