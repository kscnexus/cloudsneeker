"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

// Detection content and engine versions (EB-048).

/** `GET /content-versions`: the same for every organization. */
export const getContentVersions = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  try {
    const response = await fetch(`${apiBaseUrl}/content-versions`, {
      headers,
      cache: "no-store",
    });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};
