import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { EXECUTIVE_REPORT_FIXTURE } from "@/cloudsneeker/components/report-view.fixture";
import {
  SHARED_REPORT_STATUS,
  type SharedReportResult,
} from "@/cloudsneeker/lib/shared-report";

const getSharedReportMock = vi.fn<(token: string) => Promise<SharedReportResult>>();

vi.mock("@/cloudsneeker/actions/shared-reports", () => ({
  getSharedReport: (token: string) => getSharedReportMock(token),
}));

vi.mock("@/components/graphs", () => ({
  HorizontalBarChart: () => <div data-testid="severity-chart" />,
  LineChart: () => <div data-testid="trend-chart" />,
}));

const renderPage = async (token: string) => {
  const { default: SharedReportPage } = await import("./page");
  render(await SharedReportPage({ params: Promise.resolve({ token }) }));
};

describe("SharedReportPage", () => {
  beforeEach(() => {
    getSharedReportMock.mockReset();
  });

  it("shows a clear expired state", async () => {
    getSharedReportMock.mockResolvedValue({
      status: SHARED_REPORT_STATUS.EXPIRED,
    });

    await renderPage("expired-token-0123456789");

    expect(getSharedReportMock).toHaveBeenCalledWith(
      "expired-token-0123456789",
    );
    expect(
      screen.getByRole("heading", { name: "This link has expired" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveAttribute("data-state", "expired");
    expect(screen.getByRole("img", { name: "Cloudsneeker" })).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Key figures" })).toBeNull();
  });

  it("shows the revoked state", async () => {
    getSharedReportMock.mockResolvedValue({
      status: SHARED_REPORT_STATUS.REVOKED,
    });

    await renderPage("revoked-token-0123456789");

    expect(
      screen.getByRole("heading", { name: "This link was revoked" }),
    ).toBeInTheDocument();
  });

  it("renders the read-only report with the brand header", async () => {
    getSharedReportMock.mockResolvedValue({
      status: SHARED_REPORT_STATUS.OK,
      report: EXECUTIVE_REPORT_FIXTURE,
    });

    await renderPage("active-token-0123456789");

    expect(
      screen.getByRole("heading", { level: 1, name: "Executive summary" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/Shared report · read only/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Print/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Share/ })).toBeNull();
    expect(screen.queryByRole("link", { name: /Download/ })).toBeNull();
  });
});
