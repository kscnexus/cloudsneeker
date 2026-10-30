import { describe, expect, it } from "vitest";

import type {
  PlanFeature,
  SubscriptionAttributes,
} from "@/cloudsneeker/types/operator";

import {
  customerListParams,
  customerPageHref,
  FEATURE_OVERRIDE,
  isErrorResult,
  operatorCan,
  parseCustomerFilters,
  planPayload,
  responseError,
  responseResource,
  statusTone,
  subscriptionFormValues,
  subscriptionPayload,
  summaryFromMeta,
  UNLIMITED,
} from "./operator";

const subscription = (
  overrides: Partial<SubscriptionAttributes> = {},
): SubscriptionAttributes => ({
  tenant_id: "t-1",
  plan: "starter",
  plan_name: "Starter",
  status: "active",
  effective_status: "active",
  read_only: false,
  starts_at: "2026-01-01T00:00:00+00:00",
  ends_at: null,
  trial_ends_at: null,
  seats: null,
  feature_overrides: { audit_log: true, reports: false },
  limit_overrides: { providers: 10, users: null },
  billing_source: "manual",
  external_customer_id: "",
  notes: "",
  features: [],
  limits: {},
  updated_at: null,
  ...overrides,
});

describe("responses", () => {
  it("reads single resources and errors", () => {
    expect(responseResource({ data: { id: "x" } })).toEqual({ id: "x" });
    expect(responseResource({ data: [] })).toBeNull();
    expect(responseResource({ error: "Not found", status: 404 })).toBeNull();
    expect(responseError({ error: "Nope" })).toBe("Nope");
    expect(responseError(undefined, "Fallback")).toBe("Fallback");
    expect(isErrorResult({ error: "x" })).toBe(true);
    expect(isErrorResult({ data: {} })).toBe(false);
    expect(isErrorResult(null)).toBe(true);
  });

  it("reads the tenant summary", () => {
    expect(summaryFromMeta({ meta: { summary: { total: 3 } } })).toEqual({
      total: 3,
    });
    expect(summaryFromMeta({ error: "x" })).toBeNull();
  });

  it("checks capabilities", () => {
    expect(operatorCan({ capabilities: ["view"] }, "view")).toBe(true);
    expect(operatorCan({ capabilities: ["view"] }, "manage_plans")).toBe(false);
    expect(operatorCan(null, "view")).toBe(false);
  });

  it("maps statuses to tones", () => {
    expect(statusTone("active")).toBe("success");
    expect(statusTone("trial")).toBe("info");
    expect(statusTone("past_due")).toBe("warning");
    expect(statusTone("suspended")).toBe("danger");
  });
});

describe("customer filters", () => {
  it("parses search params and builds the API query", () => {
    const filters = parseCustomerFilters({
      search: " acme ",
      status: "suspended",
      expiring: "30d",
      over_limit: "true",
      page: "2",
    });
    expect(filters).toMatchObject({
      search: "acme",
      status: "suspended",
      expiring: "30",
      overLimit: true,
      sort: "name",
      page: 2,
    });
    expect(customerListParams(filters)).toEqual({
      "page[number]": "2",
      "page[size]": "25",
      sort: "name",
      "filter[search]": "acme",
      "filter[status]": "suspended",
      "filter[expiring_within_days]": "30",
      "filter[over_limit]": "true",
    });
    expect(customerPageHref("/operator/customers", filters, 3)).toBe(
      "/operator/customers?search=acme&status=suspended&expiring=30&over_limit=true&page=3",
    );
  });

  it("defaults bad pages to 1", () => {
    expect(parseCustomerFilters({ page: "-4" }).page).toBe(1);
    expect(parseCustomerFilters({}).page).toBe(1);
  });
});

describe("subscription editor payload", () => {
  it("round-trips overrides and dates", () => {
    const values = subscriptionFormValues(subscription());
    expect(values.startsAt).toBe("2026-01-01");
    expect(values.featureOverrides.audit_log).toBe(FEATURE_OVERRIDE.ON);
    expect(values.featureOverrides.reports).toBe(FEATURE_OVERRIDE.OFF);
    expect(values.featureOverrides.sso).toBe(FEATURE_OVERRIDE.PLAN);
    expect(values.limitOverrides.providers).toBe("10");
    expect(values.limitOverrides.users).toBe(UNLIMITED);
    expect(values.limitOverrides.report_schedules).toBe("");

    const { payload, error } = subscriptionPayload({
      ...values,
      endsAt: "2027-01-01",
      seats: "12",
    });
    expect(error).toBeNull();
    expect(payload).toMatchObject({
      plan: "starter",
      starts_at: "2026-01-01",
      ends_at: "2027-01-01",
      trial_ends_at: null,
      seats: 12,
      feature_overrides: { audit_log: true, reports: false },
      limit_overrides: { providers: 10, users: null },
    });
  });

  it("refuses bad numbers and reversed dates", () => {
    const values = subscriptionFormValues(subscription());
    expect(subscriptionPayload({ ...values, seats: "many" }).error).toContain(
      "Seats",
    );
    expect(
      subscriptionPayload({
        ...values,
        limitOverrides: { ...values.limitOverrides, providers: "-1" },
      }).error,
    ).toContain("Limit overrides");
    expect(
      subscriptionPayload({ ...values, endsAt: "2025-01-01" }).error,
    ).toContain("before the start");
  });
});

describe("plan editor payload", () => {
  const values = {
    code: "Team",
    name: " Team ",
    description: "",
    features: ["sso", "cloud_posture"] as PlanFeature[],
    limits: { providers: "5", users: "" },
    isPublic: true,
    sortOrder: "15",
  };

  it("builds the create body in catalogue order", () => {
    const { payload, error } = planPayload(values, { includeCode: true });
    expect(error).toBeNull();
    expect(payload).toMatchObject({
      code: "team",
      name: "Team",
      features: ["cloud_posture", "sso"],
      is_public: true,
      sort_order: 15,
    });
    expect(payload?.limits?.providers).toBe(5);
    expect(payload?.limits?.users).toBeNull();
  });

  it("leaves the code out of updates and validates input", () => {
    expect(
      planPayload(values, { includeCode: false }).payload?.code,
    ).toBeUndefined();
    expect(
      planPayload({ ...values, code: "bad code" }, { includeCode: true }).error,
    ).toContain("Code");
    expect(
      planPayload({ ...values, name: " " }, { includeCode: false }).error,
    ).toContain("Name");
    expect(
      planPayload(
        { ...values, limits: { providers: "x" } },
        { includeCode: false },
      ).error,
    ).toContain("whole numbers");
  });
});
