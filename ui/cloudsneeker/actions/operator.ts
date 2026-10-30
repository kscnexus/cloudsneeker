"use server";

import { revalidatePath } from "next/cache";

import { OPERATOR_ROUTE, operatorCustomerHref } from "@/cloudsneeker/routes";
import type {
  PlanWrite,
  SubscriptionUpdate,
} from "@/cloudsneeker/types/operator";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

// Operator console calls (`/api/v1/operator/*`). The API answers 404 to
// anyone without an active platform operator role, so every page treats a
// failed `getOperatorMe` as "not available".

const OPERATOR_PATH = "/operator";
const SUBSCRIPTION_TYPE = "cloudsneeker-subscriptions";
const PLAN_TYPE = "cloudsneeker-plans";

type SearchParams = Record<string, string | undefined>;

const buildUrl = (path: string, searchParams?: SearchParams): string => {
  const url = new URL(`${apiBaseUrl}${OPERATOR_PATH}${path}`);
  for (const [key, value] of Object.entries(searchParams ?? {})) {
    if (value !== undefined && value !== "")
      url.searchParams.append(key, value);
  }
  return url.toString();
};

const read = async (path: string, searchParams?: SearchParams) => {
  const headers = await getAuthHeaders({ contentType: false });
  try {
    const response = await fetch(buildUrl(path, searchParams), {
      headers,
      cache: "no-store",
    });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

const write = async (
  method: "POST" | "PATCH" | "DELETE",
  path: string,
  body?: unknown,
) => {
  const headers = await getAuthHeaders({ contentType: true });
  try {
    const response = await fetch(buildUrl(path), {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/** Role and capabilities of the signed-in operator; an error for everyone else. */
export const getOperatorMe = async () => read("/me");

/** Customer tenants with plan, status, usage and `meta.summary`. */
export const listOperatorTenants = async (searchParams?: SearchParams) =>
  read("/tenants", searchParams);

export const getOperatorTenant = async (tenantId: string) =>
  read(`/tenants/${encodeURIComponent(tenantId)}`);

export const listTenantUsageSnapshots = async (tenantId: string, days = 30) =>
  read(`/tenants/${encodeURIComponent(tenantId)}/usage-snapshots`, {
    "filter[days]": String(days),
  });

export const updateSubscription = async (
  tenantId: string,
  attributes: SubscriptionUpdate,
) => {
  const result = await write(
    "PATCH",
    `/subscriptions/${encodeURIComponent(tenantId)}`,
    { data: { type: SUBSCRIPTION_TYPE, attributes } },
  );
  revalidatePath(operatorCustomerHref(tenantId));
  revalidatePath(OPERATOR_ROUTE.CUSTOMERS);
  return result;
};

export const listPlans = async () => read("/plans");

export const createPlan = async (attributes: PlanWrite) => {
  const result = await write("POST", "/plans", {
    data: { type: PLAN_TYPE, attributes },
  });
  revalidatePath(OPERATOR_ROUTE.PLANS);
  return result;
};

export const updatePlan = async (code: string, attributes: PlanWrite) => {
  const result = await write("PATCH", `/plans/${encodeURIComponent(code)}`, {
    data: { type: PLAN_TYPE, id: code, attributes },
  });
  revalidatePath(OPERATOR_ROUTE.PLANS);
  return result;
};

export const deletePlan = async (code: string) => {
  const result = await write("DELETE", `/plans/${encodeURIComponent(code)}`);
  revalidatePath(OPERATOR_ROUTE.PLANS);
  return result;
};

export const listOperatorAuditEvents = async (searchParams?: SearchParams) =>
  read("/audit-events", searchParams);

export const listOperators = async () => read("/operators");
