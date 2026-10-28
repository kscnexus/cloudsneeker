import { describe, expect, it } from "vitest";

import type { ComplianceOverviewData } from "@/types/compliance";

import {
  SCAN_COMPARISON_DELTA,
  buildFrameworkSnapshot,
  compareFrameworks,
  complianceScore,
  parseScanComparisonParams,
  resolveDefaultScanPair,
} from "./scan-comparison";

const overview = (
  id: string,
  framework: string,
  version: string,
  passed: number,
  failed: number,
  total: number,
): ComplianceOverviewData => ({
  type: "compliance-overviews",
  id,
  attributes: {
    framework,
    version,
    requirements_passed: passed,
    requirements_failed: failed,
    requirements_manual: 0,
    total_requirements: total,
  },
});

describe("complianceScore", () => {
  it("returns the floored pass percentage", () => {
    expect(complianceScore(8, 10)).toBe(80);
    expect(complianceScore(1, 3)).toBe(33);
  });

  it("returns 0 when there are no requirements", () => {
    expect(complianceScore(0, 0)).toBe(0);
  });
});

describe("buildFrameworkSnapshot", () => {
  it("maps overview attributes into a comparable snapshot", () => {
    expect(buildFrameworkSnapshot(overview("cis-aws", "CIS", "3.0", 80, 20, 100))).toStrictEqual({
      complianceId: "cis-aws",
      framework: "CIS",
      version: "3.0",
      passed: 80,
      failed: 20,
      manual: 0,
      total: 100,
      score: 80,
    });
  });
});

describe("compareFrameworks", () => {
  it("computes score deltas and labels improved, regressed, and unchanged rows", () => {
    const baseline = [
      buildFrameworkSnapshot(overview("cis", "CIS", "3.0", 70, 30, 100)),
      buildFrameworkSnapshot(overview("iso", "ISO27001", "2022", 90, 10, 100)),
      buildFrameworkSnapshot(overview("soc", "SOC2", "", 50, 50, 100)),
    ];
    const compare = [
      buildFrameworkSnapshot(overview("cis", "CIS", "3.0", 85, 15, 100)),
      buildFrameworkSnapshot(overview("iso", "ISO27001", "2022", 80, 20, 100)),
      buildFrameworkSnapshot(overview("soc", "SOC2", "", 50, 50, 100)),
    ];

    const rows = compareFrameworks(baseline, compare);

    expect(rows).toHaveLength(3);
    expect(rows[0]).toMatchObject({
      key: "CIS|3.0",
      scoreDelta: 15,
      delta: SCAN_COMPARISON_DELTA.IMPROVED,
    });
    expect(rows[1]).toMatchObject({
      key: "ISO27001|2022",
      scoreDelta: -10,
      delta: SCAN_COMPARISON_DELTA.REGRESSED,
    });
    expect(rows[2]).toMatchObject({
      key: "SOC2|",
      scoreDelta: 0,
      delta: SCAN_COMPARISON_DELTA.UNCHANGED,
    });
  });

  it("marks frameworks only present on one side as added or removed", () => {
    const baseline = [
      buildFrameworkSnapshot(overview("old", "ENS", "RD2022", 40, 60, 100)),
    ];
    const compare = [
      buildFrameworkSnapshot(overview("new", "PCI", "4.0", 60, 40, 100)),
    ];

    const rows = compareFrameworks(baseline, compare);

    expect(rows).toStrictEqual([
      expect.objectContaining({
        key: "ENS|RD2022",
        delta: SCAN_COMPARISON_DELTA.REMOVED,
        scoreDelta: null,
        compare: null,
      }),
      expect.objectContaining({
        key: "PCI|4.0",
        delta: SCAN_COMPARISON_DELTA.ADDED,
        scoreDelta: null,
        baseline: null,
      }),
    ]);
  });

  it("sorts rows by framework then version", () => {
    const rows = compareFrameworks(
      [
        buildFrameworkSnapshot(overview("b", "CIS", "4.0", 1, 0, 1)),
        buildFrameworkSnapshot(overview("a", "AWS", "1.0", 1, 0, 1)),
      ],
      [
        buildFrameworkSnapshot(overview("b", "CIS", "3.0", 1, 0, 1)),
        buildFrameworkSnapshot(overview("a", "AWS", "1.0", 1, 0, 1)),
      ],
    );

    expect(rows.map((row) => row.key)).toStrictEqual([
      "AWS|1.0",
      "CIS|3.0",
      "CIS|4.0",
    ]);
  });
});

describe("resolveDefaultScanPair", () => {
  it("prefers the two newest scans of the same provider", () => {
    expect(
      resolveDefaultScanPair([
        { id: "aws-new", providerType: "aws" },
        { id: "azure-1", providerType: "azure" },
        { id: "aws-old", providerType: "aws" },
      ]),
    ).toStrictEqual({
      baselineScanId: "aws-old",
      compareScanId: "aws-new",
    });
  });

  it("falls back to the two newest scans when no provider has a pair", () => {
    expect(
      resolveDefaultScanPair([
        { id: "aws-1", providerType: "aws" },
        { id: "azure-1", providerType: "azure" },
      ]),
    ).toStrictEqual({
      baselineScanId: "azure-1",
      compareScanId: "aws-1",
    });
  });

  it("skips Trivy Hub scans because they carry no compliance frameworks", () => {
    expect(
      resolveDefaultScanPair([
        { id: "trivy-repo", providerType: "aws", trivyHub: true },
        { id: "aws-new", providerType: "aws" },
        { id: "aws-old", providerType: "aws" },
      ]),
    ).toStrictEqual({
      baselineScanId: "aws-old",
      compareScanId: "aws-new",
    });
  });

  it("returns null when only one compliance scan remains", () => {
    expect(
      resolveDefaultScanPair([
        { id: "trivy-repo", providerType: "aws", trivyHub: true },
        { id: "aws-1", providerType: "aws" },
      ]),
    ).toBeNull();
  });

  it("returns null when fewer than two scans exist", () => {
    expect(resolveDefaultScanPair([{ id: "only", providerType: "aws" }])).toBeNull();
    expect(resolveDefaultScanPair([])).toBeNull();
  });
});

describe("parseScanComparisonParams", () => {
  it("reads baseline and compare scan ids from search params", () => {
    expect(
      parseScanComparisonParams({
        baselineScanId: "scan-a",
        compareScanId: "scan-b",
      }),
    ).toStrictEqual({
      baselineScanId: "scan-a",
      compareScanId: "scan-b",
    });
  });

  it("ignores array and empty values", () => {
    expect(
      parseScanComparisonParams({
        baselineScanId: ["scan-a"],
        compareScanId: "",
      }),
    ).toStrictEqual({
      baselineScanId: undefined,
      compareScanId: undefined,
    });
  });
});
