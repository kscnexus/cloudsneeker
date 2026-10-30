"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

const ENTITLEMENTS_PATH = "/entitlements";

/** Plan, status, features, limits and usage of the current organization. */
export const getEntitlements = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  try {
    const response = await fetch(`${apiBaseUrl}${ENTITLEMENTS_PATH}`, {
      headers,
      cache: "no-store",
    });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};
