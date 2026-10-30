// Server-side enrichment of upstream findings responses with triage fields
// (EB-010). Upstream server actions call `withCloudsneekerTriage` through one
// `cloudsneeker-hook` line each (see knowledge-base/upstream-hooks.md).

import { isCloudsneekerFeatureEnabled } from "@/cloudsneeker/features";
import {
  findingIdsNeedingTriage,
  mergeTriageLookup,
} from "@/cloudsneeker/lib/finding-triage";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";

export const TRIAGE_LOOKUP_PATH = "/finding-triages/lookup";

/**
 * Add `triage_status`, `triage_id` and note counts to the finding rows of a
 * response. Never fails the findings request: on any error the response is
 * returned unchanged and rows read as open.
 */
export const withCloudsneekerTriage = async <T>(response: T): Promise<T> => {
  if (!isCloudsneekerFeatureEnabled("findingTriage")) return response;
  const findingIds = findingIdsNeedingTriage(response);
  if (findingIds.length === 0) return response;
  try {
    const headers = await getAuthHeaders({ contentType: false });
    const url = new URL(`${apiBaseUrl}${TRIAGE_LOOKUP_PATH}`);
    url.searchParams.set("filter[finding_id__in]", findingIds.join(","));
    const lookup = await handleApiResponse(
      await fetch(url.toString(), { headers }),
    );
    return mergeTriageLookup(response, lookup);
  } catch (error) {
    console.error("Error loading finding triage:", error);
    return response;
  }
};
