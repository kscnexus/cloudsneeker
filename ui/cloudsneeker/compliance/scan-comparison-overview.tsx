import { Info } from "lucide-react";

import { getCompliancesOverview } from "@/actions/compliances";
import { NoScansAvailable } from "@/components/compliance/no-scans-available";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { Card, CardContent } from "@/components/shadcn/card/card";
import {
  Section,
  SectionContent,
  SectionDescription,
  SectionHeader,
  SectionTitle,
} from "@/components/shadcn/section/section";
import type { ExpandedScanData, SearchParamsProps } from "@/types";
import type { ComplianceOverviewData } from "@/types/compliance";

import { ScanComparisonFilters } from "./scan-comparison-filters";
import { ScanComparisonTable } from "./scan-comparison-table";
import {
  buildFrameworkSnapshot,
  compareFrameworks,
  parseScanComparisonParams,
  resolveDefaultScanPair,
} from "./scan-comparison";

interface ScanComparisonOverviewProps {
  searchParams: SearchParamsProps;
  scans: ExpandedScanData[];
}

const isOverviewArray = (
  data: unknown,
): data is ComplianceOverviewData[] => Array.isArray(data);

const loadSnapshots = async (scanId: string) => {
  const response = await getCompliancesOverview({ scanId });
  const data = response && "data" in response ? response.data : undefined;
  if (!isOverviewArray(data)) return [];

  return data
    .filter((item) => item.attributes.framework !== "ProwlerThreatScore")
    .map(buildFrameworkSnapshot);
};

const resolveSelectedScanIds = (
  searchParams: SearchParamsProps,
  scans: ExpandedScanData[],
): { baselineScanId: string; compareScanId: string } | null => {
  const parsed = parseScanComparisonParams(searchParams);
  const defaults = resolveDefaultScanPair(
    scans.map((scan) => ({
      id: scan.id,
      providerType: scan.providerInfo.provider,
    })),
  );
  if (!defaults) return null;

  const baselineScanId =
    (parsed.baselineScanId &&
      scans.some((scan) => scan.id === parsed.baselineScanId) &&
      parsed.baselineScanId) ||
    defaults.baselineScanId;
  const compareScanId =
    (parsed.compareScanId &&
      scans.some((scan) => scan.id === parsed.compareScanId) &&
      parsed.compareScanId) ||
    defaults.compareScanId;

  return { baselineScanId, compareScanId };
};

export const ScanComparisonOverview = async ({
  searchParams,
  scans,
}: ScanComparisonOverviewProps) => {
  if (scans.length === 0) {
    return <NoScansAvailable />;
  }

  const selected = resolveSelectedScanIds(searchParams, scans);
  if (!selected) {
    return (
      <Alert variant="info">
        <Info className="size-4" />
        <AlertDescription>
          Select at least two completed scans to compare compliance results.
        </AlertDescription>
      </Alert>
    );
  }

  const { baselineScanId, compareScanId } = selected;
  const [baselineSnapshots, compareSnapshots] = await Promise.all([
    loadSnapshots(baselineScanId),
    loadSnapshots(compareScanId),
  ]);

  const rows = compareFrameworks(baselineSnapshots, compareSnapshots);
  const sameScan = baselineScanId === compareScanId;

  return (
    <div className="flex flex-col gap-6">
      <ScanComparisonFilters
        scans={scans}
        baselineScanId={baselineScanId}
        compareScanId={compareScanId}
      />

      {sameScan && (
        <Alert variant="info">
          <Info className="size-4" />
          <AlertDescription>
            Baseline and compare point at the same scan. Choose a second scan to
            see score changes.
          </AlertDescription>
        </Alert>
      )}

      <Section>
        <SectionHeader>
          <SectionTitle>Compare scans</SectionTitle>
          <SectionDescription>
            Framework pass rates for the baseline scan versus the compare scan.
            Positive change means the compare scan passed a larger share of
            requirements.
          </SectionDescription>
        </SectionHeader>
        <SectionContent>
          <Card variant="base" padding="none" className="w-full shadow-sm">
            <CardContent className="p-4">
              <ScanComparisonTable rows={rows} />
            </CardContent>
          </Card>
        </SectionContent>
      </Section>
    </div>
  );
};
