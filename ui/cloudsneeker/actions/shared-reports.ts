"use server";

import {
  isPlausibleShareToken,
  SHARED_REPORT_STATUS,
  sharedReportResultFromResponse,
  type SharedReportResult,
} from "@/cloudsneeker/lib/shared-report";
import { apiBaseUrl } from "@/lib";

/**
 * Public read of a shared report. Sends no session headers: the API endpoint
 * is unauthenticated and enforces expiry, revocation, and a per-IP limit.
 */
export const getSharedReport = async (
  token: string,
): Promise<SharedReportResult> => {
  if (!isPlausibleShareToken(token)) {
    return { status: SHARED_REPORT_STATUS.NOT_FOUND };
  }
  try {
    const response = await fetch(
      `${apiBaseUrl}/shared-reports/${encodeURIComponent(token)}`,
      {
        headers: { Accept: "application/vnd.api+json" },
        cache: "no-store",
      },
    );
    const body: unknown = await response.json().catch(() => null);
    return sharedReportResultFromResponse(response.status, body);
  } catch {
    return { status: SHARED_REPORT_STATUS.UNAVAILABLE };
  }
};
