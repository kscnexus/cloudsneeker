import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { TargetReportDownloadButton } from "./target-report-download-button";

const { startMock, statusMock, listMock } = vi.hoisted(() => ({
  startMock: vi.fn(),
  statusMock: vi.fn(),
  listMock: vi.fn(),
}));

vi.mock("@/cloudsneeker/actions/target-reports", () => ({
  startTargetReport: startMock,
  getTargetReportStatuses: statusMock,
  listRepositoryReportJobs: listMock,
}));

const job = {
  targetId: "target-1",
  targetName: "payments-api",
  reportType: "sca" as const,
};

describe("TargetReportDownloadButton", () => {
  let clicked: string[];

  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    startMock.mockReset();
    statusMock.mockReset();
    listMock.mockReset();
    clicked = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clicked.push(this.getAttribute("href") ?? "");
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("generates the target's report and downloads it when ready", async () => {
    startMock.mockResolvedValue({ runId: "run-1" });
    statusMock.mockResolvedValue({ "run-1": "completed" });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(
      <TargetReportDownloadButton label="Download SCA report" jobs={[job]} />,
    );

    await user.click(
      screen.getByRole("button", { name: "Download SCA report" }),
    );
    await vi.advanceTimersByTimeAsync(5000);

    await waitFor(() => expect(clicked).toHaveLength(1));
    expect(startMock).toHaveBeenCalledWith("target-1", "sca");
    expect(clicked[0]).toBe(
      "/api/cloudsneeker/reports/run-1/download?format=pdf",
    );
    expect(
      await screen.findByText("1 of 1 reports downloaded"),
    ).toBeInTheDocument();
  });

  it("loads every repository target when no jobs are given", async () => {
    listMock.mockResolvedValue({
      jobs: [job, { ...job, targetId: "target-2", reportType: "sast" }],
    });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    startMock
      .mockResolvedValueOnce({ runId: "run-1" })
      .mockResolvedValueOnce({ runId: "run-2" });
    statusMock.mockResolvedValue({ "run-1": "completed", "run-2": "failed" });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(<TargetReportDownloadButton label="Download all" />);

    await user.click(screen.getByRole("button", { name: "Download all" }));
    await vi.advanceTimersByTimeAsync(5000);

    expect(
      await screen.findByText("1 of 2 reports downloaded (1 failed)"),
    ).toBeInTheDocument();
    expect(startMock).toHaveBeenCalledWith("target-2", "sast");
    expect(clicked).toHaveLength(1);
  });

  it("does nothing when the bulk download is not confirmed", async () => {
    listMock.mockResolvedValue({ jobs: [job, { ...job, targetId: "t2" }] });
    vi.spyOn(window, "confirm").mockReturnValue(false);
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(<TargetReportDownloadButton label="Download all" />);

    await user.click(screen.getByRole("button", { name: "Download all" }));

    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Download all" }),
      ).toBeEnabled(),
    );
    expect(startMock).not.toHaveBeenCalled();
  });

  it("shows the API error when the report cannot start", async () => {
    startMock.mockResolvedValue({
      error: "This report does not cover IaC targets.",
    });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    render(
      <TargetReportDownloadButton label="Download SCA report" jobs={[job]} />,
    );

    await user.click(
      screen.getByRole("button", { name: "Download SCA report" }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "This report does not cover IaC targets.",
    );
    expect(clicked).toHaveLength(0);
  });
});
