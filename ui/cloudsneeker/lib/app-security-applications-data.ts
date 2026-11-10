// Server-side loaders for the Application Inventory and detail pages.

import { listAreaFindings } from "@/cloudsneeker/actions/finding-triage";
import { listTrivyTargets } from "@/cloudsneeker/actions/trivy";
import { responseApplicationSummaries } from "@/cloudsneeker/lib/app-security-applications";
import { responsePages } from "@/cloudsneeker/lib/app-security-scan-history";
import {
  isListResponse,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import {
  type AreaApplicationSummary,
  type AreaFindingsResponse,
  FINDING_AREA,
} from "@/cloudsneeker/types/area-findings";
import type { TrivyTargetResource } from "@/cloudsneeker/types/trivy";

/** The API pages at 100; 20 pages hold 2,000 targets. */
const TARGET_PAGE_SIZE = 100;
const MAX_TARGET_PAGES = 20;

export interface LoadedTargets {
  targets: TrivyTargetResource[];
  /** More pages exist than were read. */
  truncated: boolean;
}

/** Every target (optionally of one provider); null when the first page fails. */
export const loadAllTargets = async (
  filters: Record<string, string> = {},
): Promise<LoadedTargets | null> => {
  const targets: TrivyTargetResource[] = [];
  for (let page = 1; page <= MAX_TARGET_PAGES; page += 1) {
    const response = await listTrivyTargets({
      ...filters,
      "page[size]": String(TARGET_PAGE_SIZE),
      "page[number]": String(page),
      sort: "-inserted_at",
    });
    if (!isListResponse(response)) {
      return page === 1 ? null : { targets, truncated: true };
    }
    targets.push(...responseList<TrivyTargetResource>(response));
    if (page >= responsePages(response)) return { targets, truncated: false };
  }
  return { targets, truncated: true };
};

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
