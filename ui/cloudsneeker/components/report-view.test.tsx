import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ReportView } from "./report-view";
import { EXECUTIVE_REPORT_FIXTURE } from "./report-view.fixture";

// Charts need layout measurements jsdom does not provide; assert the data
// handed to them instead.
vi.mock("@/components/graphs", () => ({
  HorizontalBarChart: ({ data }: { data: { name: string; value: number }[] }) => (
    <ul data-testid="severity-chart">
      {data.map((item) => (
        <li key={item.name}>{`${item.name}: ${item.value}`}</li>
      ))}
    </ul>
  ),
  LineChart: ({ data }: { data: unknown[] }) => (
    <div data-testid="trend-chart">{data.length} points</div>
  ),
}));

describe("ReportView", () => {
  it("renders the headline, grade, KPIs and charts", () => {
    render(<ReportView report={EXECUTIVE_REPORT_FIXTURE} />);

    expect(
      screen.getByRole("heading", { level: 1, name: "Executive summary" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("42 open issue(s) across 3 source(s), 5 critical."),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: /Security score 72 of 100, grade C/ }),
    ).toBeInTheDocument();

    const kpis = screen.getByRole("list", { name: "Key figures" });
    expect(within(kpis).getByText("Open issues")).toBeInTheDocument();
    expect(within(kpis).getByText("42")).toBeInTheDocument();
    expect(within(kpis).getByText("81%")).toBeInTheDocument();

    expect(screen.getByTestId("severity-chart")).toHaveTextContent(
      "Critical: 5",
    );
    expect(screen.getByTestId("trend-chart")).toHaveTextContent("2 points");
    expect(screen.getByText(/High and above/)).toBeInTheDocument();
  });

  it("shows risks with business impact, posture and next actions", () => {
    render(<ReportView report={EXECUTIVE_REPORT_FIXTURE} />);

    expect(
      screen.getByText("S3 bucket allows public access"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Customer data could be read by anyone on the internet."),
    ).toBeInTheDocument();
    expect(screen.getByText("Cloud posture")).toBeInTheDocument();
    expect(
      screen.getByRole("progressbar", { name: "CIS 2.0 AWS pass rate" }),
    ).toHaveAttribute("aria-valuenow", "81");
    expect(
      screen.getByText("Fix the 5 critical issue(s) this week."),
    ).toBeInTheDocument();
  });

  it("paginates detail tables", async () => {
    const user = userEvent.setup();
    render(<ReportView report={EXECUTIVE_REPORT_FIXTURE} />);

    expect(screen.getByText("Area 1")).toBeInTheDocument();
    expect(screen.queryByText("Area 26")).not.toBeInTheDocument();
    expect(screen.getByText("Page 1 of 2")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Next" }));

    expect(screen.getByText("Area 26")).toBeInTheDocument();
    expect(screen.getByText("Page 2 of 2")).toBeInTheDocument();
  });

  it("shows the empty state instead of charts", () => {
    render(
      <ReportView
        report={{
          ...EXECUTIVE_REPORT_FIXTURE,
          empty_state: "No static analysis scans yet.",
          kpis: {},
          top_risks: [],
          tables: [],
        }}
      />,
    );

    expect(screen.getByText("No static analysis scans yet.")).toBeInTheDocument();
    expect(screen.queryByTestId("severity-chart")).not.toBeInTheDocument();
  });

  it("renders header actions and never names an engine", () => {
    const { container } = render(
      <ReportView
        report={EXECUTIVE_REPORT_FIXTURE}
        actions={<button type="button">Print</button>}
      />,
    );

    expect(screen.getByRole("button", { name: "Print" })).toBeInTheDocument();
    expect(container.textContent).not.toMatch(
      /prowler|trivy|custodian|opengrep|semgrep/i,
    );
  });
});
