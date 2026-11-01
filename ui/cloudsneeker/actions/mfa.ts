"use server";

import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

// Multi-factor authentication (EB-008). Secrets and recovery codes come back
// once in the action result; they are never cached or logged here.

const MFA_PATH = "/mfa";

const send = async (
  path: string,
  method: "POST" | "PATCH",
  resourceType: string,
  attributes: Record<string, unknown> = {},
) => {
  const headers = await getAuthHeaders({ contentType: true });
  try {
    const response = await fetch(`${apiBaseUrl}${MFA_PATH}${path}`, {
      method,
      headers,
      cache: "no-store",
      body: JSON.stringify({ data: { type: resourceType, attributes } }),
    });
    return handleApiResponse(response, PRODUCT_ROUTE.SECURITY);
  } catch (error) {
    return handleApiError(error);
  }
};

/** `GET /mfa`: the signed-in user's MFA state and the tenant requirement. */
export const getMfaStatus = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  try {
    const response = await fetch(`${apiBaseUrl}${MFA_PATH}`, {
      headers,
      cache: "no-store",
    });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/** Starts setup: a new secret and `otpauth://` URI. */
export const startMfaEnrolment = async () =>
  send("/enrolment", "POST", "cloudsneeker-mfa-enrolments");

/** Confirms setup with a first code; returns the recovery codes. */
export const confirmMfaEnrolment = async (code: string) =>
  send("/enrolment/confirm", "POST", "cloudsneeker-mfa-enrolments", { code });

export const regenerateMfaRecoveryCodes = async (code: string) =>
  send("/recovery-codes", "POST", "cloudsneeker-mfa-recovery-codes", { code });

export const disableMfa = async (code: string) =>
  send("/disable", "POST", "cloudsneeker-mfa-enrolments", { code });

/** Tenant requirement; the API checks the manage account permission. */
export const setTenantMfaRequirement = async (requireMfa: boolean) =>
  send("/policy", "PATCH", "cloudsneeker-mfa-policies", {
    require_mfa: requireMfa,
  });
