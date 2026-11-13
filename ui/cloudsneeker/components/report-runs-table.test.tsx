import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: vi.fn() }) }));
vi.mock("@/cloudsneeker/actions/reports", () => ({ deleteReportRun: vi.fn() }));
vi.mock("./report-share-dialog", () => ({ ReportShareDialog: () => null }));

import { ReportRunsTable } from "./report-runs-table";

describe("ReportRunsTable empty state", () => {
  it("says no report matches when filters are applied", () => {
    render(<ReportRunsTable runs={[]} canShare filtered />);
    expect(screen.getByText("No reports match")).toBeInTheDocument();
  });

  it("invites a first report when nothing is filtered", () => {
    render(<ReportRunsTable runs={[]} canShare />);
    expect(screen.getByText("No reports yet")).toBeInTheDocument();
  });
});
