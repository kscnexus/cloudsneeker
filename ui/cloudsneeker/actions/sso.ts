"use server";

import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

// SAML options per organization (EB-009).

const SSO_POLICY_PATH = "/sso/policy";

/** `GET /sso/policy`: IdP-initiated setting and the signing state. */
export const getSsoPolicy = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  try {
    const response = await fetch(`${apiBaseUrl}${SSO_POLICY_PATH}`, {
      headers,
      cache: "no-store",
    });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/** Admins only; the API checks the manage account permission. */
export const setRejectIdpInitiatedSso = async (reject: boolean) => {
  const headers = await getAuthHeaders({ contentType: true });
  try {
    const response = await fetch(`${apiBaseUrl}${SSO_POLICY_PATH}`, {
      method: "PATCH",
      headers,
      cache: "no-store",
      body: JSON.stringify({
        data: {
          type: "cloudsneeker-sso-policies",
          attributes: { reject_idp_initiated_sso: reject },
        },
      }),
    });
    return handleApiResponse(response, PRODUCT_ROUTE.SECURITY);
  } catch (error) {
    return handleApiError(error);
  }
};
