// Which scan the Compliance page opens when the URL names none. Upstream takes
// the newest completed scan, but IaC and container image scans have no
// compliance frameworks, so a fresh code scan left the page empty while
// Overview listed dozens of frameworks for the cloud scans.

import type { ExpandedScanData } from "@/types";

export const PROVIDERS_WITHOUT_COMPLIANCE: ReadonlySet<string> = new Set([
  "iac",
  "image",
]);

/** The newest scan with compliance data, else the newest scan. */
export const defaultComplianceScanId = (
  scans: ExpandedScanData[],
): string | undefined =>
  (
    scans.find(
      (scan) => !PROVIDERS_WITHOUT_COMPLIANCE.has(scan.providerInfo?.provider),
    ) ?? scans[0]
  )?.id;
