import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SCAN_COMPARISON_DELTA } from "./scan-comparison";
import { ScanComparisonTable } from "./scan-comparison-table";

describe("ScanComparisonTable", () => {
  it("renders framework scores and change labels", () => {
    render(
      <ScanComparisonTable
        rows={[
          {
            key: "CIS|3.0",
            framework: "CIS",
            version: "3.0",
            baseline: {
              complianceId: "cis",
              framework: "CIS",
              version: "3.0",
              passed: 70,
              failed: 30,
              manual: 0,
              total: 100,
              score: 70,
            },
            compare: {
              complianceId: "cis",
              framework: "CIS",
              version: "3.0",
              passed: 85,
              failed: 15,
              manual: 0,
              total: 100,
              score: 85,
            },
            scoreDelta: 15,
            delta: SCAN_COMPARISON_DELTA.IMPROVED,
          },
        ]}
      />,
    );

    expect(screen.getByText(/CIS/i)).toBeInTheDocument();
    expect(screen.getByText("70% (70/100)")).toBeInTheDocument();
    expect(screen.getByText("85% (85/100)")).toBeInTheDocument();
    expect(screen.getByText("+15 pp")).toBeInTheDocument();
    expect(screen.getByText("Improved")).toBeInTheDocument();
  });

  it("shows an empty message when there are no rows", () => {
    render(<ScanComparisonTable rows={[]} />);

    expect(
      screen.getByText(/No compliance frameworks to compare/i),
    ).toBeInTheDocument();
  });
});
