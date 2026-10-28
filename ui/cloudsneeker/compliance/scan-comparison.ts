import type { ComplianceOverviewData } from "@/types/compliance";
import type { SearchParamsProps } from "@/types";

export const SCAN_COMPARISON_DELTA = {
  IMPROVED: "improved",
  REGRESSED: "regressed",
  UNCHANGED: "unchanged",
  ADDED: "added",
  REMOVED: "removed",
} as const;

export type ScanComparisonDelta =
  (typeof SCAN_COMPARISON_DELTA)[keyof typeof SCAN_COMPARISON_DELTA];

export interface FrameworkSnapshot {
  complianceId: string;
  framework: string;
  version: string;
  passed: number;
  failed: number;
  manual: number;
  total: number;
  score: number;
}

export interface FrameworkComparisonRow {
  key: string;
  framework: string;
  version: string;
  baseline: FrameworkSnapshot | null;
  compare: FrameworkSnapshot | null;
  scoreDelta: number | null;
  delta: ScanComparisonDelta;
}

export interface ScanPairCandidate {
  id: string;
  providerType: string;
  /** Imported by Trivy Hub; such scans have no compliance frameworks. */
  trivyHub?: boolean;
}

export const TRIVY_HUB_SCAN_SOURCE = "trivy_hub";

export function isTrivyHubScan(scannerArgs: unknown): boolean {
  if (!scannerArgs || typeof scannerArgs !== "object") return false;
  return (
    (scannerArgs as { source?: unknown }).source === TRIVY_HUB_SCAN_SOURCE
  );
}

export interface ResolvedScanPair {
  baselineScanId: string;
  compareScanId: string;
}

export interface ParsedScanComparisonParams {
  baselineScanId: string | undefined;
  compareScanId: string | undefined;
}

export function complianceScore(passed: number, total: number): number {
  if (total <= 0) return 0;
  return Math.floor((passed / total) * 100);
}

export function frameworkComparisonKey(
  framework: string,
  version: string,
): string {
  return `${framework}|${version}`;
}

export function buildFrameworkSnapshot(
  overview: ComplianceOverviewData,
): FrameworkSnapshot {
  const { framework, version, requirements_passed, requirements_failed, requirements_manual, total_requirements } =
    overview.attributes;

  return {
    complianceId: overview.id,
    framework,
    version,
    passed: requirements_passed,
    failed: requirements_failed,
    manual: requirements_manual,
    total: total_requirements,
    score: complianceScore(requirements_passed, total_requirements),
  };
}

function classifyDelta(
  baseline: FrameworkSnapshot | null,
  compare: FrameworkSnapshot | null,
): { delta: ScanComparisonDelta; scoreDelta: number | null } {
  if (baseline && !compare) {
    return { delta: SCAN_COMPARISON_DELTA.REMOVED, scoreDelta: null };
  }
  if (!baseline && compare) {
    return { delta: SCAN_COMPARISON_DELTA.ADDED, scoreDelta: null };
  }
  if (!baseline || !compare) {
    return { delta: SCAN_COMPARISON_DELTA.UNCHANGED, scoreDelta: null };
  }

  const scoreDelta = compare.score - baseline.score;
  if (scoreDelta > 0) {
    return { delta: SCAN_COMPARISON_DELTA.IMPROVED, scoreDelta };
  }
  if (scoreDelta < 0) {
    return { delta: SCAN_COMPARISON_DELTA.REGRESSED, scoreDelta };
  }
  return { delta: SCAN_COMPARISON_DELTA.UNCHANGED, scoreDelta: 0 };
}

export function compareFrameworks(
  baseline: FrameworkSnapshot[],
  compare: FrameworkSnapshot[],
): FrameworkComparisonRow[] {
  const baselineByKey = new Map(
    baseline.map((snapshot) => [
      frameworkComparisonKey(snapshot.framework, snapshot.version),
      snapshot,
    ]),
  );
  const compareByKey = new Map(
    compare.map((snapshot) => [
      frameworkComparisonKey(snapshot.framework, snapshot.version),
      snapshot,
    ]),
  );

  const keys = new Set([
    ...Array.from(baselineByKey.keys()),
    ...Array.from(compareByKey.keys()),
  ]);

  return Array.from(keys)
    .map((key) => {
      const baselineSnapshot = baselineByKey.get(key) ?? null;
      const compareSnapshot = compareByKey.get(key) ?? null;
      const sample = compareSnapshot ?? baselineSnapshot;
      const { delta, scoreDelta } = classifyDelta(
        baselineSnapshot,
        compareSnapshot,
      );

      return {
        key,
        framework: sample?.framework ?? "",
        version: sample?.version ?? "",
        baseline: baselineSnapshot,
        compare: compareSnapshot,
        scoreDelta,
        delta,
      };
    })
    .sort((left, right) => {
      const frameworkOrder = left.framework.localeCompare(right.framework);
      if (frameworkOrder !== 0) return frameworkOrder;
      return left.version.localeCompare(right.version);
    });
}

export function resolveDefaultScanPair(
  candidates: ScanPairCandidate[],
): ResolvedScanPair | null {
  const scans = candidates.filter((scan) => !scan.trivyHub);
  if (scans.length < 2) return null;

  const byProvider = new Map<string, ScanPairCandidate[]>();
  for (const scan of scans) {
    const group = byProvider.get(scan.providerType) ?? [];
    group.push(scan);
    byProvider.set(scan.providerType, group);
  }

  for (const group of Array.from(byProvider.values())) {
    if (group.length >= 2) {
      return {
        baselineScanId: group[1].id,
        compareScanId: group[0].id,
      };
    }
  }

  return {
    baselineScanId: scans[1].id,
    compareScanId: scans[0].id,
  };
}

const readParam = (
  value: string | string[] | undefined,
): string | undefined => {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
};

export function parseScanComparisonParams(
  searchParams: SearchParamsProps | Record<string, string | string[] | undefined>,
): ParsedScanComparisonParams {
  return {
    baselineScanId: readParam(searchParams.baselineScanId),
    compareScanId: readParam(searchParams.compareScanId),
  };
}
