"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

const POLICIES_PATH = "/custodian-policies";
const RUNS_PATH = "/custodian-runs";
const REVALIDATE_PATH = "/custodian";

const POLICY_TYPE = "cloudsneeker-custodian-policies";

export interface CustodianPolicyPayload {
  name: string;
  description?: string;
  policyYaml: string;
  providerId: string;
}

const buildPolicyEnvelope = (
  payload: CustodianPolicyPayload,
  policyId?: string,
) => ({
  data: {
    type: POLICY_TYPE,
    ...(policyId ? { id: policyId } : {}),
    attributes: {
      name: payload.name,
      description: payload.description ?? "",
      policy_yaml: payload.policyYaml,
      provider_id: payload.providerId,
    },
  },
});

export const listCustodianPolicies = async (
  searchParams?: Record<string, string | undefined>,
) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${POLICIES_PATH}`);

  if (searchParams) {
    for (const [key, value] of Object.entries(searchParams)) {
      if (value !== undefined && value !== "") {
        url.searchParams.append(key, value);
      }
    }
  }

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

export const getCustodianPolicy = async (policyId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${POLICIES_PATH}/${policyId}`);

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

export const createCustodianPolicy = async (payload: CustodianPolicyPayload) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}${POLICIES_PATH}`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(buildPolicyEnvelope(payload)),
    });
    const result = await handleApiResponse(response, REVALIDATE_PATH);
    revalidatePath(REVALIDATE_PATH);
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};

export const updateCustodianPolicy = async (
  policyId: string,
  payload: CustodianPolicyPayload,
) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}${POLICIES_PATH}/${policyId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(buildPolicyEnvelope(payload, policyId)),
    });
    const result = await handleApiResponse(response, REVALIDATE_PATH);
    revalidatePath(`${REVALIDATE_PATH}/${policyId}`);
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};

export const deleteCustodianPolicy = async (policyId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${POLICIES_PATH}/${policyId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });
    const result = await handleApiResponse(response, REVALIDATE_PATH);
    revalidatePath(REVALIDATE_PATH);
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};

export const dryRunCustodianPolicy = async (policyId: string) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}${POLICIES_PATH}/${policyId}/dry-run`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: { type: "cloudsneeker-custodian-runs", attributes: {} },
      }),
    });
    const result = await handleApiResponse(response);
    revalidatePath(`${REVALIDATE_PATH}/${policyId}`);
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};

export const listCustodianRuns = async (
  searchParams?: Record<string, string | undefined>,
) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${RUNS_PATH}`);

  if (searchParams) {
    for (const [key, value] of Object.entries(searchParams)) {
      if (value !== undefined && value !== "") {
        url.searchParams.append(key, value);
      }
    }
  }

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};
