"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

const TRIAGES_PATH = "/finding-triages";

type SearchParams = Record<string, string | undefined>;

const buildUrl = (path: string, searchParams?: SearchParams): string => {
  const url = new URL(`${apiBaseUrl}${path}`);
  for (const [key, value] of Object.entries(searchParams ?? {})) {
    if (value !== undefined && value !== "") {
      url.searchParams.append(key, value);
    }
  }
  return url.toString();
};

/** `GET /finding-triages` (status, assignee, check and provider filters). */
export const listFindingTriages = async (searchParams?: SearchParams) => {
  const headers = await getAuthHeaders({ contentType: false });
  try {
    const response = await fetch(buildUrl(TRIAGES_PATH, searchParams), {
      headers,
    });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};
