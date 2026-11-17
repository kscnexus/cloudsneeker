// Monthly assistant allowance (EB-080). The chat runs in the web app, so the
// chat route records each request with the API before it runs. The API
// answers 403 when the plan's monthly allowance is used; anything else
// (network error, older API, server error) lets the chat continue.

import { createUIMessageStreamResponse } from "ai";

import { apiBaseUrl, getAuthHeaders } from "@/lib/helper";
import {
  createTextDeltaEvent,
  createTextEndEvent,
  createTextStartEvent,
  ERROR_PREFIX,
  STREAM_MESSAGE_ID,
} from "@/lib/lighthouse-v1/analyst-stream";

const SEEKER_AI_REQUESTS_PATH = "/seeker-ai/requests";
const FORBIDDEN = 403;

export const SEEKER_AI_DENIAL_FALLBACK =
  "This organization's plan does not allow more assistant requests this month.";

interface ApiError {
  detail?: unknown;
}

interface ApiErrorDocument {
  errors?: ApiError[];
}

/**
 * Records one assistant request. Returns the reason when the plan refuses
 * it, or `null` when the chat may run.
 */
export const recordSeekerAiRequest = async (): Promise<string | null> => {
  try {
    const headers = await getAuthHeaders({ contentType: true });
    const response = await fetch(`${apiBaseUrl}${SEEKER_AI_REQUESTS_PATH}`, {
      method: "POST",
      headers,
      cache: "no-store",
    });
    if (response.status !== FORBIDDEN) return null;
    const document = (await response
      .json()
      .catch(() => null)) as ApiErrorDocument | null;
    const detail = document?.errors?.[0]?.detail;
    return typeof detail === "string" && detail
      ? detail
      : SEEKER_AI_DENIAL_FALLBACK;
  } catch {
    return null;
  }
};

/**
 * The chat response for a refused request, or `null` to run the chat. The
 * reason travels as an error message in the stream, which the chat already
 * shows above the input and removes from the history.
 */
export const seekerAiAllowanceResponse = async (): Promise<Response | null> => {
  const reason = await recordSeekerAiRequest();
  if (reason === null) return null;
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(createTextStartEvent(STREAM_MESSAGE_ID));
      controller.enqueue(
        createTextDeltaEvent(STREAM_MESSAGE_ID, `${ERROR_PREFIX} ${reason}`),
      );
      controller.enqueue(createTextEndEvent(STREAM_MESSAGE_ID));
      controller.close();
    },
  });
  return createUIMessageStreamResponse({ stream });
};
