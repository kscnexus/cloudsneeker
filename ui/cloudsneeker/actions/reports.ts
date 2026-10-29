"use server";

import { revalidatePath } from "next/cache";

import {
  buildReportRunEnvelope,
  buildReportScheduleEnvelope,
  buildScheduleToggleEnvelope,
  buildShareLinkEnvelope,
  type ReportRunPayload,
  type ReportSchedulePayload,
} from "@/cloudsneeker/lib/report-form-schema";
import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import { REPORT_RESOURCE_TYPE } from "@/cloudsneeker/types/reports";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

const TYPES_PATH = "/report-types";
const RUNS_PATH = "/report-runs";
const SCHEDULES_PATH = "/report-schedules";
const SHARE_LINKS_PATH = "/report-share-links";
const REVALIDATE_PATH = PRODUCT_ROUTE.REPORTS;

type SearchParams = Record<string, string | undefined>;

const buildUrl = (path: string, searchParams?: SearchParams): string => {
  const url = new URL(`${apiBaseUrl}${path}`);
  if (searchParams) {
    for (const [key, value] of Object.entries(searchParams)) {
      if (value !== undefined && value !== "") {
        url.searchParams.append(key, value);
      }
    }
  }
  return url.toString();
};

const getJson = async (path: string, searchParams?: SearchParams) => {
  const headers = await getAuthHeaders({ contentType: false });
  try {
    const response = await fetch(buildUrl(path, searchParams), { headers });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

const send = async (
  method: "POST" | "PATCH" | "DELETE",
  path: string,
  body?: unknown,
) => {
  const headers = await getAuthHeaders({ contentType: body !== undefined });
  try {
    const response = await fetch(buildUrl(path), {
      method,
      headers,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    const result = await handleApiResponse(response, REVALIDATE_PATH);
    revalidatePath(REVALIDATE_PATH);
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};

const segment = (value: string): string => encodeURIComponent(value);

export const listReportTypes = async () => getJson(TYPES_PATH);

export const listReportRuns = async (searchParams?: SearchParams) =>
  getJson(RUNS_PATH, searchParams);

export const getReportRun = async (runId: string) =>
  getJson(`${RUNS_PATH}/${segment(runId)}`);

export const getReportRunData = async (runId: string) =>
  getJson(`${RUNS_PATH}/${segment(runId)}/data`);

export const createReportRun = async (payload: ReportRunPayload) =>
  send("POST", RUNS_PATH, buildReportRunEnvelope(payload));

export const deleteReportRun = async (runId: string) =>
  send("DELETE", `${RUNS_PATH}/${segment(runId)}`);

export const listRunShareLinks = async (runId: string) =>
  getJson(`${RUNS_PATH}/${segment(runId)}/share-links`);

/** Returns the raw token once, in `data.attributes.token`. */
export const createReportShareLink = async (
  runId: string,
  expiresInHours: number,
) =>
  send(
    "POST",
    `${RUNS_PATH}/${segment(runId)}/share-links`,
    buildShareLinkEnvelope(expiresInHours),
  );

export const listReportShareLinks = async (searchParams?: SearchParams) =>
  getJson(SHARE_LINKS_PATH, searchParams);

export const revokeReportShareLink = async (linkId: string) =>
  send("POST", `${SHARE_LINKS_PATH}/${segment(linkId)}/revoke`, {
    data: {
      type: REPORT_RESOURCE_TYPE.REPORT_SHARE_LINKS,
      id: linkId,
      attributes: {},
    },
  });

export const listReportSchedules = async (searchParams?: SearchParams) =>
  getJson(SCHEDULES_PATH, searchParams);

export const createReportSchedule = async (payload: ReportSchedulePayload) =>
  send("POST", SCHEDULES_PATH, buildReportScheduleEnvelope(payload));

export const updateReportSchedule = async (
  scheduleId: string,
  payload: ReportSchedulePayload,
) =>
  send(
    "PATCH",
    `${SCHEDULES_PATH}/${segment(scheduleId)}`,
    buildReportScheduleEnvelope(payload, scheduleId),
  );

export const setReportScheduleEnabled = async (
  scheduleId: string,
  enabled: boolean,
) =>
  send(
    "PATCH",
    `${SCHEDULES_PATH}/${segment(scheduleId)}`,
    buildScheduleToggleEnvelope(scheduleId, enabled),
  );

export const deleteReportSchedule = async (scheduleId: string) =>
  send("DELETE", `${SCHEDULES_PATH}/${segment(scheduleId)}`);
