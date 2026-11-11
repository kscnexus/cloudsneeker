import { getComplianceOverviewMetadataInfo } from "@/actions/compliances";

import type {
  ComplianceMetadata,
  ComplianceMetadataLoader,
} from "./scan-availability";

/** Compliance metadata of one scan; null when the API reports a server error
 * (the scan's compliance task failed). Other failures keep the upstream
 * behaviour: the page renders with no regions. */
export const loadComplianceMetadata: ComplianceMetadataLoader = async (
  scanId,
) => {
  try {
    const response = (await getComplianceOverviewMetadataInfo({
      filters: { "filter[scan_id]": scanId },
    })) as ComplianceMetadata | undefined;
    return response ?? {};
  } catch {
    return null;
  }
};
