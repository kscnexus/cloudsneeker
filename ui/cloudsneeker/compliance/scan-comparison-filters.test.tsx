import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ScanComparisonFilters } from "./scan-comparison-filters";

const { pushMock, searchParamsMock } = vi.hoisted(() => ({
  pushMock: vi.fn(),
  searchParamsMock: new URLSearchParams(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
  useSearchParams: () => searchParamsMock,
}));

vi.mock("@/components/compliance/compliance-header/scan-selector", () => ({
  ScanSelector: ({
    selectedScanId,
    onSelectionChange,
  }: {
    selectedScanId: string;
    onSelectionChange: (value: string) => void;
  }) => (
    <button
      type="button"
      onClick={() => onSelectionChange("scan-next")}
    >{`selected:${selectedScanId}`}</button>
  ),
}));

const scans = [
  {
    id: "scan-a",
    type: "scans",
    attributes: {
      name: "A",
      completed_at: "2026-01-01T00:00:00Z",
    },
    relationships: {
      provider: { data: { id: "provider-1", type: "providers" } },
    },
    providerInfo: {
      provider: "aws" as const,
      uid: "111",
      alias: "Prod",
    },
  },
  {
    id: "scan-b",
    type: "scans",
    attributes: {
      name: "B",
      completed_at: "2026-01-02T00:00:00Z",
    },
    relationships: {
      provider: { data: { id: "provider-1", type: "providers" } },
    },
    providerInfo: {
      provider: "aws" as const,
      uid: "111",
      alias: "Prod",
    },
  },
];

describe("ScanComparisonFilters", () => {
  beforeEach(() => {
    pushMock.mockClear();
    for (const key of [...searchParamsMock.keys()]) {
      searchParamsMock.delete(key);
    }
  });

  it("updates the compare scan in the URL without pinning Single Scan", async () => {
    const user = userEvent.setup();
    render(
      <ScanComparisonFilters
        scans={scans}
        baselineScanId="scan-a"
        compareScanId="scan-b"
      />,
    );

    expect(screen.getByText("Baseline scan")).toBeInTheDocument();
    expect(screen.getByText("Compare scan")).toBeInTheDocument();

    const buttons = screen.getAllByRole("button");
    await user.click(buttons[1]);

    expect(pushMock).toHaveBeenCalledWith(
      "/compliance?baselineScanId=scan-a&compareScanId=scan-next",
      { scroll: false },
    );
  });
});
