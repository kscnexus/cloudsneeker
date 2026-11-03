"use server";

import { revalidatePath } from "next/cache";

import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

const LIBRARY_PATH = "/custodian-library";
const LIBRARY_TYPE = "cloudsneeker-custodian-library-policies";
const REVALIDATE_PATH = PRODUCT_ROUTE.GOVERNANCE;

export interface LibraryListParams {
  providerType?: string;
  category?: string;
  search?: string;
  starter?: boolean;
}

export const listCustodianLibrary = async (params: LibraryListParams = {}) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${LIBRARY_PATH}`);
  if (params.providerType) {
    url.searchParams.set("provider_type", params.providerType);
  }
  if (params.category) url.searchParams.set("category", params.category);
  if (params.search) url.searchParams.set("search", params.search);
  if (params.starter) url.searchParams.set("starter", "true");

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

const postLibrary = async (
  path: string,
  attributes: Record<string, unknown>,
  revalidate: boolean,
) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}${LIBRARY_PATH}/${path}`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify({ data: { type: LIBRARY_TYPE, attributes } }),
    });
    const result = await handleApiResponse(
      response,
      revalidate ? REVALIDATE_PATH : undefined,
    );
    if (revalidate) revalidatePath(REVALIDATE_PATH);
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};

export const installCustodianLibraryPolicies = async (payload: {
  providerId: string;
  policyIds: string[];
}) =>
  postLibrary(
    "install",
    { provider_id: payload.providerId, policy_ids: payload.policyIds },
    true,
  );

export const generateCustodianPolicyDraft = async (payload: {
  providerType: string;
  prompt: string;
  resourceType?: string;
}) =>
  postLibrary(
    "generate",
    {
      provider_type: payload.providerType,
      prompt: payload.prompt,
      resource_type: payload.resourceType ?? "",
    },
    false,
  );

export const validateCustodianPolicyYaml = async (payload: {
  providerType: string;
  policyYaml: string;
}) =>
  postLibrary(
    "validate",
    { provider_type: payload.providerType, policy_yaml: payload.policyYaml },
    false,
  );
