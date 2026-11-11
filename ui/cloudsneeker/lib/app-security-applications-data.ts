// Server-side loaders for the Application Inventory and detail pages.

import { listAreaFindings } from "@/cloudsneeker/actions/finding-triage";
import { responseApplicationSummaries } from "@/cloudsneeker/lib/app-security-applications";
import {
  isListResponse,
} from "@/cloudsneeker/lib/findings-links";
import {
  type AreaApplicationSummary,
  type AreaFindingsResponse,
  FINDING_AREA,
} from "@/cloudsneeker/types/area-findings";

export {
  loadAllTargets,
  type LoadedTargets,
} from "@/cloudsneeker/lib/trivy-targets-data";

/** Open finding counts per application; null when the request fails. */
export const loadApplicationSummaries = async (): Promise<
  AreaApplicationSummary[] | null
> => {
  const response: unknown = await listAreaFindings({
    "filter[area]": FINDING_AREA.APPLICATION_SECURITY,
    summary: "applications",
    "page[size]": "1",
  });
  return isListResponse(response)
    ? responseApplicationSummaries(response)
    : null;
};

/** Category, priority and overdue counts of one application's findings. */
export const loadApplicationFindingMeta = async (
  applicationId: string,
): Promise<AreaFindingsResponse["meta"] | null> => {
  const response: unknown = await listAreaFindings({
    "filter[area]": FINDING_AREA.APPLICATION_SECURITY,
    "filter[application__in]": applicationId,
    "page[size]": "1",
  });
  if (!isListResponse(response)) return null;
  return (response as AreaFindingsResponse).meta ?? {};
};
