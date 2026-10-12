"use server";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";

import type { BrandResponse } from "../types/brand";

export const getBrand = async (): Promise<BrandResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/cloudsneeker/brand`);

  try {
    const response = await fetch(url.toString(), {
      method: "GET",
      headers,
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch brand: ${response.statusText}`);
    }

    return (await handleApiResponse(response)) as BrandResponse;
  } catch (error) {
    console.error("Error fetching brand:", error);
    return undefined;
  }
};
