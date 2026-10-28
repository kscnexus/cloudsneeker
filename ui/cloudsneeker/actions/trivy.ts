"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

const TARGETS_PATH = "/trivy-targets";
const RUNS_PATH = "/trivy-runs";
const REVALIDATE_PATH = "/trivy";

const TARGET_TYPE = "cloudsneeker-trivy-targets";

export interface TrivyTargetPayload {
  name: string;
  description?: string;
  mode: string;
  providerId: string;
  config?: Record<string, unknown>;
  scheduleEnabled?: boolean;
  scheduleCron?: string;
  scheduleTimezone?: string;
}

const buildTargetEnvelope = (
  payload: TrivyTargetPayload,
  targetId?: string,
) => ({
  data: {
    type: TARGET_TYPE,
    ...(targetId ? { id: targetId } : {}),
    attributes: {
      name: payload.name,
      description: payload.description ?? "",
      mode: payload.mode,
      provider_id: payload.providerId,
      config: payload.config ?? {},
      schedule_enabled: payload.scheduleEnabled ?? false,
      schedule_cron: payload.scheduleCron ?? "",
      schedule_timezone: payload.scheduleTimezone ?? "UTC",
    },
  },
});

export const listTrivyTargets = async (
  searchParams?: Record<string, string | undefined>,
) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${TARGETS_PATH}`);

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

export const getTrivyTarget = async (targetId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${TARGETS_PATH}/${targetId}`);

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

export const createTrivyTarget = async (payload: TrivyTargetPayload) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}${TARGETS_PATH}`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(buildTargetEnvelope(payload)),
    });
    const result = await handleApiResponse(response, REVALIDATE_PATH);
    revalidatePath(REVALIDATE_PATH);
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};

export const updateTrivyTarget = async (
  targetId: string,
  payload: TrivyTargetPayload,
) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}${TARGETS_PATH}/${targetId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(buildTargetEnvelope(payload, targetId)),
    });
    const result = await handleApiResponse(response, REVALIDATE_PATH);
    revalidatePath(`${REVALIDATE_PATH}/${targetId}`);
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};

export const deleteTrivyTarget = async (targetId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${TARGETS_PATH}/${targetId}`);

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

export const scanTrivyTarget = async (targetId: string) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}${TARGETS_PATH}/${targetId}/scan`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: { type: "cloudsneeker-trivy-runs", attributes: {} },
      }),
    });
    const result = await handleApiResponse(response);
    revalidatePath(`${REVALIDATE_PATH}/${targetId}`);
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};

export const listTrivyRuns = async (
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

export const getTrivyRun = async (runId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${RUNS_PATH}/${runId}`);

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};
