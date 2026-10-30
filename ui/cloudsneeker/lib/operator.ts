// Pure helpers for the operator console pages: response guards, customer
// list filters, and the subscription and plan editor payloads.

import type { StatTileTone } from "@/cloudsneeker/components/stat-tile";
import {
  PLAN_FEATURES,
  PLAN_LIMITS,
  READ_ONLY_STATUSES,
} from "@/cloudsneeker/lib/entitlements";
import {
  type BillingSource,
  type OperatorCapability,
  type OperatorMeAttributes,
  type OperatorTenantSummary,
  type PlanFeature,
  type PlanLimits,
  type PlanWrite,
  SUBSCRIPTION_STATUS,
  type SubscriptionAttributes,
  type SubscriptionStatus,
  type SubscriptionUpdate,
} from "@/cloudsneeker/types/operator";

export const OPERATOR_PAGE_SIZE = 25;

/** Tone of a status pill or tile. */
export const statusTone = (status: SubscriptionStatus): StatTileTone => {
  if (READ_ONLY_STATUSES.includes(status)) return "danger";
  if (status === SUBSCRIPTION_STATUS.PAST_DUE) return "warning";
  if (status === SUBSCRIPTION_STATUS.TRIAL) return "info";
  return "success";
};

export const BILLING_SOURCE_LABEL: Record<BillingSource, string> = {
  manual: "Manual",
  aws_marketplace: "AWS Marketplace",
  azure_marketplace: "Azure Marketplace",
  self_hosted_licence: "Self-hosted licence",
};

// --- Responses -------------------------------------------------------------------

const asRecord = (value: unknown): Record<string, unknown> | null =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;

/** `data` of a single-resource response, or `null` on an error result. */
export const responseResource = <T>(response: unknown): T | null => {
  const data = asRecord(response)?.data;
  return asRecord(data) ? (data as T) : null;
};

/** Error text of a failed action result. */
export const responseError = (
  response: unknown,
  fallback = "The request failed. Try again in a moment.",
): string => {
  const error = asRecord(response)?.error;
  return typeof error === "string" && error ? error : fallback;
};

export const isErrorResult = (response: unknown): boolean => {
  const record = asRecord(response);
  return !record || typeof record.error === "string";
};

export const operatorCan = (
  me: Pick<OperatorMeAttributes, "capabilities"> | null,
  capability: OperatorCapability,
): boolean => Boolean(me?.capabilities.includes(capability));

export const summaryFromMeta = (
  response: unknown,
): OperatorTenantSummary | null => {
  const summary = asRecord(asRecord(asRecord(response)?.meta)?.summary);
  if (!summary || typeof summary.total !== "number") return null;
  return summary as unknown as OperatorTenantSummary;
};

// --- Customer list filters ---------------------------------------------------------

export interface CustomerFilters {
  search: string;
  status: string;
  plan: string;
  expiring: string;
  overLimit: boolean;
  sort: string;
  page: number;
}

const first = (value: string | string[] | undefined): string =>
  (Array.isArray(value) ? value[0] : value)?.trim() ?? "";

export const parseCustomerFilters = (
  params: Record<string, string | string[] | undefined>,
): CustomerFilters => {
  const page = Number.parseInt(first(params.page), 10);
  return {
    search: first(params.search),
    status: first(params.status),
    plan: first(params.plan),
    expiring: first(params.expiring).replace(/\D/g, ""),
    overLimit: first(params.over_limit) === "true",
    sort: first(params.sort) || "name",
    page: Number.isFinite(page) && page > 0 ? page : 1,
  };
};

/** Query for `GET /operator/tenants`. */
export const customerListParams = (
  filters: CustomerFilters,
): Record<string, string> => {
  const params: Record<string, string> = {
    "page[number]": String(filters.page),
    "page[size]": String(OPERATOR_PAGE_SIZE),
    sort: filters.sort,
  };
  if (filters.search) params["filter[search]"] = filters.search;
  if (filters.status) params["filter[status]"] = filters.status;
  if (filters.plan) params["filter[plan]"] = filters.plan;
  if (filters.expiring)
    params["filter[expiring_within_days]"] = filters.expiring;
  if (filters.overLimit) params["filter[over_limit]"] = "true";
  return params;
};

/** Customer list URL with the filters and a page. */
export const customerPageHref = (
  base: string,
  filters: CustomerFilters,
  page: number,
): string => {
  const query = new URLSearchParams();
  if (filters.search) query.set("search", filters.search);
  if (filters.status) query.set("status", filters.status);
  if (filters.plan) query.set("plan", filters.plan);
  if (filters.expiring) query.set("expiring", filters.expiring);
  if (filters.overLimit) query.set("over_limit", "true");
  if (filters.sort && filters.sort !== "name") query.set("sort", filters.sort);
  if (page > 1) query.set("page", String(page));
  const text = query.toString();
  return text ? `${base}?${text}` : base;
};

// --- Subscription editor -----------------------------------------------------------

/** Three-way feature toggle: follow the plan, force on, force off. */
export const FEATURE_OVERRIDE = {
  PLAN: "plan",
  ON: "on",
  OFF: "off",
} as const;

export type FeatureOverride =
  (typeof FEATURE_OVERRIDE)[keyof typeof FEATURE_OVERRIDE];

export interface SubscriptionFormValues {
  plan: string;
  status: SubscriptionStatus;
  startsAt: string;
  endsAt: string;
  trialEndsAt: string;
  seats: string;
  billingSource: BillingSource;
  externalCustomerId: string;
  notes: string;
  featureOverrides: Record<PlanFeature, FeatureOverride>;
  /** Empty string = follow the plan; "unlimited" or a number overrides it. */
  limitOverrides: Record<string, string>;
}

export const UNLIMITED = "unlimited";

/** `YYYY-MM-DD` of an ISO timestamp, for date inputs. */
export const toDateInput = (value: string | null | undefined): string =>
  value ? value.slice(0, 10) : "";

export const subscriptionFormValues = (
  subscription: SubscriptionAttributes,
): SubscriptionFormValues => {
  const featureOverrides = {} as Record<PlanFeature, FeatureOverride>;
  for (const feature of PLAN_FEATURES) {
    const value = subscription.feature_overrides?.[feature];
    featureOverrides[feature] =
      value === true
        ? FEATURE_OVERRIDE.ON
        : value === false
          ? FEATURE_OVERRIDE.OFF
          : FEATURE_OVERRIDE.PLAN;
  }
  const limitOverrides: Record<string, string> = {};
  for (const key of PLAN_LIMITS) {
    const overrides = subscription.limit_overrides ?? {};
    if (!(key in overrides)) {
      limitOverrides[key] = "";
      continue;
    }
    const value = overrides[key];
    limitOverrides[key] = typeof value === "number" ? String(value) : UNLIMITED;
  }
  return {
    plan: subscription.plan,
    status: subscription.status,
    startsAt: toDateInput(subscription.starts_at),
    endsAt: toDateInput(subscription.ends_at),
    trialEndsAt: toDateInput(subscription.trial_ends_at),
    seats: subscription.seats === null ? "" : String(subscription.seats),
    billingSource: subscription.billing_source,
    externalCustomerId: subscription.external_customer_id ?? "",
    notes: subscription.notes ?? "",
    featureOverrides,
    limitOverrides,
  };
};

export interface PayloadResult<T> {
  payload: T | null;
  error: string | null;
}

const parseCount = (value: string): number | null | undefined => {
  const text = value.trim();
  if (text === "") return undefined;
  if (!/^\d+$/.test(text)) return null;
  return Number.parseInt(text, 10);
};

/** Form values -> PATCH body (dates as ISO dates, blank = cleared). */
export const subscriptionPayload = (
  values: SubscriptionFormValues,
): PayloadResult<SubscriptionUpdate> => {
  const featureOverrides: Partial<Record<PlanFeature, boolean>> = {};
  for (const feature of PLAN_FEATURES) {
    const choice = values.featureOverrides[feature];
    if (choice === FEATURE_OVERRIDE.ON) featureOverrides[feature] = true;
    if (choice === FEATURE_OVERRIDE.OFF) featureOverrides[feature] = false;
  }
  const limitOverrides: PlanLimits = {};
  for (const key of PLAN_LIMITS) {
    const raw = (values.limitOverrides[key] ?? "").trim().toLowerCase();
    if (raw === "") continue;
    if (raw === UNLIMITED) {
      limitOverrides[key] = null;
      continue;
    }
    const count = parseCount(raw);
    if (count === null || count === undefined) {
      return {
        payload: null,
        error: "Limit overrides must be whole numbers or 'unlimited'.",
      };
    }
    limitOverrides[key] = count;
  }
  const seats = parseCount(values.seats);
  if (seats === null) {
    return { payload: null, error: "Seats must be a whole number." };
  }
  if (values.endsAt && values.startsAt && values.endsAt < values.startsAt) {
    return { payload: null, error: "The end date is before the start date." };
  }
  return {
    error: null,
    payload: {
      plan: values.plan,
      status: values.status,
      starts_at: values.startsAt || null,
      ends_at: values.endsAt || null,
      trial_ends_at: values.trialEndsAt || null,
      seats: seats ?? null,
      billing_source: values.billingSource,
      external_customer_id: values.externalCustomerId.trim(),
      notes: values.notes,
      feature_overrides: featureOverrides,
      limit_overrides: limitOverrides,
    },
  };
};

// --- Plan editor -------------------------------------------------------------------

export interface PlanFormValues {
  code: string;
  name: string;
  description: string;
  features: PlanFeature[];
  /** Empty string = unlimited. */
  limits: Record<string, string>;
  isPublic: boolean;
  sortOrder: string;
}

export const planPayload = (
  values: PlanFormValues,
  { includeCode }: { includeCode: boolean },
): PayloadResult<PlanWrite> => {
  const code = values.code.trim().toLowerCase();
  if (includeCode && !/^[a-z0-9][a-z0-9_-]{0,49}$/.test(code)) {
    return {
      payload: null,
      error: "Code: lowercase letters, numbers, - and _ (up to 50).",
    };
  }
  if (!values.name.trim()) return { payload: null, error: "Name is required." };
  const limits: PlanLimits = {};
  for (const key of PLAN_LIMITS) {
    const count = parseCount(values.limits[key] ?? "");
    if (count === null) {
      return { payload: null, error: "Limits must be whole numbers." };
    }
    limits[key] = count ?? null;
  }
  const sortOrder = Number.parseInt(values.sortOrder || "100", 10);
  const payload: PlanWrite = {
    name: values.name.trim(),
    description: values.description.trim(),
    features: PLAN_FEATURES.filter((feature) =>
      values.features.includes(feature),
    ),
    limits,
    is_public: values.isPublic,
    sort_order: Number.isFinite(sortOrder) ? sortOrder : 100,
  };
  if (includeCode) payload.code = code;
  return { payload, error: null };
};
