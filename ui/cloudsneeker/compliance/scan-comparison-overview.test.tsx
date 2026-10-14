import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ScanComparisonOverview } from "./scan-comparison-overview";

const { getCompliancesOverviewMock } = vi.hoisted(() => ({
  getCompliancesOverviewMock: vi.fn(),
}));

vi.mock("@/actions/compliances", () => ({
  getCompliancesOverview: getCompliancesOverviewMock,
}));

vi.mock("@/components/compliance", () => ({
  NoScansAvailable: () => <div>No scans available</div>,
}));

vi.mock("./scan-comparison-filters", () => ({
  ScanComparisonFilters: ({
    baselineScanId,
    compareScanId,
  }: {
    baselineScanId: string;
    compareScanId: string;
  }) => (
    <div>{`filters:${baselineScanId}->${compareScanId}`}</div>
  ),
}));

vi.mock("./scan-comparison-table", () => ({
  ScanComparisonTable: ({
    rows,
  }: {
    rows: Array<{ key: string; scoreDelta: number | null }>;
  }) => (
    <div>
      {rows.map((row) => (
        <div key={row.key}>{`row:${row.key}:${row.scoreDelta}`}</div>
      ))}
    </div>
  ),
}));

const scans = [
  {
    id: "scan-new",
    type: "scans" as const,
    attributes: {
      name: "New",
      completed_at: "2026-02-01T00:00:00Z",
    },
    relationships: {
      provider: { data: { id: "provider-1", type: "providers" as const } },
    },
    providerInfo: {
      provider: "aws" as const,
      uid: "111",
      alias: "Prod",
    },
  },
  {
    id: "scan-old",
    type: "scans" as const,
    attributes: {
      name: "Old",
      completed_at: "2026-01-01T00:00:00Z",
    },
    relationships: {
      provider: { data: { id: "provider-1", type: "providers" as const } },
    },
    providerInfo: {
      provider: "aws" as const,
      uid: "111",
      alias: "Prod",
    },
  },
];

describe("ScanComparisonOverview", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getCompliancesOverviewMock.mockImplementation(({ scanId }: { scanId: string }) => {
      if (scanId === "scan-old") {
        return {
          data: [
            {
              id: "cis",
              type: "compliance-overviews",
              attributes: {
                framework: "CIS",
                version: "3.0",
                requirements_passed: 70,
                requirements_failed: 30,
                requirements_manual: 0,
                total_requirements: 100,
              },
            },
          ],
        };
      }
      return {
        data: [
          {
            id: "cis",
            type: "compliance-overviews",
            attributes: {
              framework: "CIS",
              version: "3.0",
              requirements_passed: 85,
              requirements_failed: 15,
              requirements_manual: 0,
              total_requirements: 100,
            },
          },
        ],
      };
    });
  });

  it("compares the two newest same-provider scans by default", async () => {
    render(
      await ScanComparisonOverview({
        searchParams: {},
        scans,
      }),
    );

    expect(screen.getByText("filters:scan-old->scan-new")).toBeInTheDocument();
    expect(screen.getByText("Compare scans")).toBeInTheDocument();
    expect(screen.getByText("row:CIS|3.0:15")).toBeInTheDocument();
  });

  it("asks for a second scan when fewer than two exist", async () => {
    render(
      await ScanComparisonOverview({
        searchParams: {},
        scans: [scans[0]],
      }),
    );

    expect(
      screen.getByText(/Select at least two completed scans/i),
    ).toBeInTheDocument();
  });
});
