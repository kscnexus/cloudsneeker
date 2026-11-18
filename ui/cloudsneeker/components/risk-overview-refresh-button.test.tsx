import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { RiskOverviewRefreshButton } from "./risk-overview-refresh-button";

const { createReportRunMock, refreshMock } = vi.hoisted(() => ({
  createReportRunMock: vi.fn(),
  refreshMock: vi.fn(),
}));

vi.mock("@/cloudsneeker/actions/reports", () => ({
  createReportRun: createReportRunMock,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: refreshMock }),
}));

describe("RiskOverviewRefreshButton", () => {
  beforeEach(() => {
    createReportRunMock.mockReset();
    refreshMock.mockReset();
    window.sessionStorage.clear();
  });

  it("starts an executive report and refreshes the page", async () => {
    createReportRunMock.mockResolvedValue({ data: { id: "run-2" } });
    const user = userEvent.setup();
    render(<RiskOverviewRefreshButton label="Refresh" />);

    await user.click(screen.getByRole("button", { name: "Refresh" }));

    expect(createReportRunMock).toHaveBeenCalledWith({
      reportType: "executive",
      params: {},
      formats: ["pdf"],
    });
    expect(refreshMock).toHaveBeenCalledTimes(1);
  });

  it("shows the API error and does not refresh", async () => {
    createReportRunMock.mockResolvedValue({ error: "Report limit reached." });
    const user = userEvent.setup();
    render(<RiskOverviewRefreshButton label="Build risk view" />);

    await user.click(screen.getByRole("button", { name: "Build risk view" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Report limit reached.",
    );
    expect(refreshMock).not.toHaveBeenCalled();
  });

  it("starts a run on its own once for an out-of-date snapshot", async () => {
    createReportRunMock.mockResolvedValue({ data: { id: "run-2" } });
    const { unmount } = render(
      <RiskOverviewRefreshButton label="Refresh" autoStartKey="run-1" />,
    );
    await waitFor(() => expect(refreshMock).toHaveBeenCalledTimes(1));
    expect(createReportRunMock).toHaveBeenCalledTimes(1);
    unmount();

    // A second visit in the same session does not start another run.
    render(<RiskOverviewRefreshButton label="Refresh" autoStartKey="run-1" />);
    expect(createReportRunMock).toHaveBeenCalledTimes(1);
  });

  it("starts nothing without an out-of-date snapshot", () => {
    render(<RiskOverviewRefreshButton label="Refresh" />);
    expect(createReportRunMock).not.toHaveBeenCalled();
  });
});
