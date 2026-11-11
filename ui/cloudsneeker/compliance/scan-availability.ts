// Which scan Single Scan opens, given that a scan's compliance data can be
// missing. The API builds compliance results in a background task after the
// scan; when that task failed (for example, a worker restart mid-run), the
// metadata endpoint answers 500 "Task failed to generate compliance overview
// data", and the upstream page turned that into its error screen. The default
// scan now skips such scans, and a scan named in the URL shows a notice.

import { PROVIDERS_WITHOUT_COMPLIANCE } from "./default-scan";

/** How many default candidates are tried before giving up. */
export const COMPLIANCE_DEFAULT_CANDIDATES = 5;

export interface ComplianceMetadata {
  data?: { attributes?: { regions?: string[] } };
}

/** Metadata of a scan, or null when its compliance data failed to build. */
export type ComplianceMetadataLoader = (
  scanId: string,
) => Promise<ComplianceMetadata | null>;

export interface ComplianceScanSelection {
  scanId: string | null;
  metadata: ComplianceMetadata | null;
  /** The selected scan has no compliance data to show. */
  unavailable: boolean;
}

interface CandidateScan {
  id: string;
  providerInfo?: { provider?: string };
}

export const selectComplianceScan = async (
  urlScanId: string | undefined,
  scans: CandidateScan[],
  load: ComplianceMetadataLoader,
): Promise<ComplianceScanSelection> => {
  if (urlScanId) {
    const metadata = await load(urlScanId);
    return { scanId: urlScanId, metadata, unavailable: metadata === null };
  }

  const withFrameworks = scans.filter(
    (scan) =>
      !PROVIDERS_WITHOUT_COMPLIANCE.has(scan.providerInfo?.provider ?? ""),
  );
  const candidates = withFrameworks.length > 0 ? withFrameworks : scans;
  if (candidates.length === 0) {
    return { scanId: null, metadata: null, unavailable: false };
  }

  for (const scan of candidates.slice(0, COMPLIANCE_DEFAULT_CANDIDATES)) {
    const metadata = await load(scan.id);
    if (metadata !== null) {
      return { scanId: scan.id, metadata, unavailable: false };
    }
  }
  return { scanId: candidates[0].id, metadata: null, unavailable: true };
};
