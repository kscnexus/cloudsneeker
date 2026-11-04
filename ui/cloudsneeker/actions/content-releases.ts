"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

// Detection content release notes (EB-049).

/** `GET /content-releases`: newest first, the same for every organization. */
export const getContentReleases = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  try {
    const response = await fetch(`${apiBaseUrl}/content-releases`, {
      headers,
      cache: "no-store",
    });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};
