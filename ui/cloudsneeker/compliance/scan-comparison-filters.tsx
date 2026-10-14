"use client";

import { useRouter, useSearchParams } from "next/navigation";

import { ScanSelector } from "@/components/compliance/compliance-header/scan-selector";
import type { SelectScanComplianceDataProps } from "@/components/compliance/compliance-header/scan-selector";

interface ScanComparisonFiltersProps {
  scans: SelectScanComplianceDataProps["scans"];
  baselineScanId: string;
  compareScanId: string;
}

export const ScanComparisonFilters = ({
  scans,
  baselineScanId,
  compareScanId,
}: ScanComparisonFiltersProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const updateScanParam = (
    key: "baselineScanId" | "compareScanId",
    value: string,
  ) => {
    const params = new URLSearchParams(searchParams.toString());
    // Keep both selections in the URL so changing one side does not reset
    // the other to the page defaults.
    params.set(
      "baselineScanId",
      key === "baselineScanId" ? value : baselineScanId,
    );
    params.set(
      "compareScanId",
      key === "compareScanId" ? value : compareScanId,
    );
    // Multiple Scans owns the bare route; drop Single Scan tab pins.
    params.delete("tab");
    params.delete("scanId");
    router.push(`/compliance?${params.toString()}`, { scroll: false });
  };

  return (
    <div className="flex max-w-4xl flex-wrap items-center gap-4">
      <div className="w-full sm:max-w-[380px] sm:min-w-[200px] sm:flex-1">
        <label className="text-text-neutral-secondary mb-1.5 block text-xs font-medium">
          Baseline scan
        </label>
        <ScanSelector
          scans={scans}
          selectedScanId={baselineScanId}
          onSelectionChange={(value) => updateScanParam("baselineScanId", value)}
        />
      </div>
      <div className="w-full sm:max-w-[380px] sm:min-w-[200px] sm:flex-1">
        <label className="text-text-neutral-secondary mb-1.5 block text-xs font-medium">
          Compare scan
        </label>
        <ScanSelector
          scans={scans}
          selectedScanId={compareScanId}
          onSelectionChange={(value) => updateScanParam("compareScanId", value)}
        />
      </div>
    </div>
  );
};
