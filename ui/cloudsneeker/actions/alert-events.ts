"use server";

import { revalidatePath } from "next/cache";

import {
  type AlertEventStatus,
  isAlertEventStatus,
} from "@/cloudsneeker/lib/alert-history";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

const EVENTS_PATH = "/alerts/events";
const REVALIDATE_PATH = "/alerts";
const NOTE_MAX_LENGTH = 2000;

export const listAlertEvents = async (query: Record<string, string>) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}${EVENTS_PATH}`);
  Object.entries(query).forEach(([key, value]) => {
    if (value) url.searchParams.append(key, value);
  });

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

export interface AlertEventUpdate {
  status?: AlertEventStatus;
  note?: string;
}

/** Acknowledge, resolve, dismiss or reopen an alert event, or edit its note. */
export const updateAlertEvent = async (
  eventId: string,
  update: AlertEventUpdate,
) => {
  if (update.status !== undefined && !isAlertEventStatus(update.status)) {
    return { error: "Unknown alert status." };
  }
  if (update.note !== undefined && update.note.length > NOTE_MAX_LENGTH) {
    return { error: `Notes are limited to ${NOTE_MAX_LENGTH} characters.` };
  }
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(
    `${apiBaseUrl}${EVENTS_PATH}/${encodeURIComponent(eventId)}`,
  );

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        data: {
          type: "alert-events",
          id: eventId,
          attributes: {
            ...(update.status !== undefined ? { status: update.status } : {}),
            ...(update.note !== undefined ? { note: update.note } : {}),
          },
        },
      }),
    });
    const result = await handleApiResponse(response, REVALIDATE_PATH);
    revalidatePath(REVALIDATE_PATH);
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};
