"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import type { FindingTriageStatus } from "@/types/findings-triage";

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

// --- Area findings and triage ---

const AREA_FINDINGS_PATH = "/area-findings";
const AREA_PAGE_PATHS = [
  "/triage",
  "/application-security/findings",
  "/application-security/triage",
  "/governance/findings",
  "/governance/triage",
] as const;

const revalidateAreaPages = () => {
  for (const path of AREA_PAGE_PATHS) revalidatePath(path);
};

/** `GET /area-findings` (area, severity, triage, source, search, sort, page). */
export const listAreaFindings = async (searchParams: SearchParams) => {
  const headers = await getAuthHeaders({ contentType: false });
  try {
    const response = await fetch(buildUrl(AREA_FINDINGS_PATH, searchParams), {
      headers,
    });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/** Set the triage status (and optional note) of one finding UID. */
export const updateFindingTriage = async (
  findingUid: string,
  attributes: {
    status?: FindingTriageStatus;
    note?: string;
    /** EB-019: only with `risk_accepted`. */
    risk_reason?: string;
    risk_expires_on?: string;
  },
) => {
  const headers = await getAuthHeaders({ contentType: true });
  try {
    const response = await fetch(
      buildUrl(`/findings/${encodeURIComponent(findingUid)}/triage`),
      {
        method: "PATCH",
        headers,
        body: JSON.stringify({
          data: { type: "finding-triages", attributes },
        }),
      },
    );
    const result = await handleApiResponse(response);
    revalidateAreaPages();
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};

/** Set one status on many finding UIDs (`POST /finding-triages/bulk`). */
export const bulkUpdateFindingTriage = async (
  findingUids: string[],
  status: FindingTriageStatus,
  note?: string,
  acceptance?: { risk_reason: string; risk_expires_on: string },
) => {
  const headers = await getAuthHeaders({ contentType: true });
  try {
    const response = await fetch(buildUrl(`${TRIAGES_PATH}/bulk`), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: "finding-triages",
          attributes: {
            finding_uids: findingUids,
            status,
            ...(note ? { note } : {}),
            ...(acceptance ?? {}),
          },
        },
      }),
    });
    const result = await handleApiResponse(response);
    revalidateAreaPages();
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};

/** Mute findings of any area through the shared mutelist
 * (`POST /area-findings/mute`). Muted findings leave the active views and
 * stay readable with the muted filter. */
export const muteAreaFindings = async (input: {
  findingUids: string[];
  name: string;
  reason: string;
}) => {
  const headers = await getAuthHeaders({ contentType: true });
  try {
    const response = await fetch(buildUrl(`${AREA_FINDINGS_PATH}/mute`), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: "mute-rules",
          attributes: {
            finding_uids: input.findingUids,
            name: input.name,
            reason: input.reason,
          },
        },
      }),
    });
    const result = await handleApiResponse(response);
    revalidateAreaPages();
    revalidatePath("/mutelist");
    revalidatePath("/application-security", "layout");
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};
