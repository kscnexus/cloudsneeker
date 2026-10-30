"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

const AUDIT_EVENTS_PATH = "/audit-events";

/** One page of the tenant audit log (`GET /audit-events`). Read-only. */
export const listAuditEvents = async (searchParams: Record<string, string>) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${AUDIT_EVENTS_PATH}`);
  for (const [key, value] of Object.entries(searchParams)) {
    if (value) url.searchParams.append(key, value);
  }
  try {
    const response = await fetch(url.toString(), { headers, cache: "no-store" });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};
