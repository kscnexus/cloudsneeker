import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { usePlanStore } from "@/cloudsneeker/lib/plan-store";
import type {
  OperatorTenantResource,
  SubscriptionEventResource,
} from "@/cloudsneeker/types/operator";

import { CustomerTable } from "./customer-table";
import { isOperatorLinkActive } from "./operator-nav";
import { PlanStateInitializer } from "./plan-state-initializer";
import { PlanSummary } from "./plan-summary";
import { SubscriptionBanner } from "./subscription-banner";
import { describeChange, SubscriptionHistory } from "./subscription-history";
import { SubscriptionStatusBadge } from "./subscription-status-badge";
import { UsageBars } from "./usage-bars";

const tenant: OperatorTenantResource = {
  type: "cloudsneeker-operator-tenants",
  id: "tenant-1",
  attributes: {
    name: "Acme",
    inserted_at: null,
    plan: "starter",
    plan_name: "Starter",
    status: "active",
    effective_status: "suspended",
    read_only: true,
    starts_at: null,
    ends_at: "2027-03-01T00:00:00+00:00",
    trial_ends_at: null,
    billing_source: "manual",
    member_count: 4,
    last_activity: null,
    usage: { providers: 5 },
    limits: { providers: 3 },
    features: [],
    over_limit: ["providers"],
  },
};

describe("SubscriptionBanner", () => {
  it("is an alert for read-only organizations", () => {
    render(
      <SubscriptionBanner
        banner={{
          tone: "danger",
          title: "Subscription expired",
          message: "Renew",
        }}
      />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("Subscription expired");
  });

  it("is a status message for a trial ending", () => {
    render(
      <SubscriptionBanner
        banner={{
          tone: "warning",
          title: "Your trial ends in 2 days",
          message: "x",
        }}
      />,
    );
    expect(screen.getByRole("status")).toHaveTextContent(
      "Your trial ends in 2 days",
    );
  });
});

describe("UsageBars", () => {
  it("shows usage against each limit and flags overuse", () => {
    render(
      <UsageBars
        usage={{ providers: 5, users: 1 }}
        limits={{ providers: 3 }}
      />,
    );
    expect(screen.getByText("5 / 3")).toHaveClass("text-text-error-primary");
    expect(screen.getByText("1 / Unlimited")).toBeInTheDocument();
    expect(
      screen.getByRole("progressbar", { name: "Providers" }),
    ).toHaveAttribute("aria-valuenow", "100");
  });
});

describe("CustomerTable", () => {
  it("links each customer and shows the over-limit reason", () => {
    render(<CustomerTable tenants={[tenant]} />);
    expect(screen.getByRole("link", { name: "Acme" })).toHaveAttribute(
      "href",
      "/operator/customers/tenant-1",
    );
    expect(screen.getByText(/Over limit: Providers/)).toBeInTheDocument();
    expect(screen.getByText("Suspended")).toBeInTheDocument();
    expect(screen.getByText("5 / 3")).toBeInTheDocument();
  });
});

describe("SubscriptionStatusBadge", () => {
  it("labels the status", () => {
    render(<SubscriptionStatusBadge status="past_due" />);
    expect(screen.getByText("Past due")).toHaveAttribute(
      "data-status",
      "past_due",
    );
  });
});

describe("SubscriptionHistory", () => {
  it("describes changes without free-text values", () => {
    expect(describeChange("plan", { from: "legacy", to: "starter" })).toBe(
      "Plan: legacy to starter",
    );
    expect(describeChange("notes", { changed: true })).toBe("Notes changed");
    expect(
      describeChange("ends_at", {
        from: null,
        to: "2027-01-01T00:00:00+00:00",
      }),
    ).toBe("Ends: none to 2027-01-01");
    expect(
      describeChange("feature_overrides", { from: {}, to: { sso: true } }),
    ).toBe("Feature toggles changed");

    const events: SubscriptionEventResource[] = [
      {
        type: "cloudsneeker-subscription-events",
        id: "e-1",
        attributes: {
          tenant_id: "t",
          action: "expired",
          source: "system",
          changes: { status: { from: "active", to: "expired" } },
          actor_id: null,
          actor_email: "",
          inserted_at: "2026-10-31T00:00:00+00:00",
        },
      },
    ];
    render(<SubscriptionHistory events={events} />);
    expect(screen.getByText("Subscription expired")).toBeInTheDocument();
    expect(screen.getByText("Status: active to expired")).toBeInTheDocument();
    expect(screen.getByText("System")).toBeInTheDocument();
  });
});

describe("PlanSummary", () => {
  it("shows plan name, status and end date", () => {
    render(
      <PlanSummary
        entitlements={{
          plan: { code: "starter", name: "Starter" },
          status: "active",
          effective_status: "active",
          read_only: false,
          features: [],
          limits: { providers: 3 },
          usage: { providers: 1 },
          over_limit: [],
          starts_at: null,
          ends_at: "2027-01-15T00:00:00+00:00",
          trial_ends_at: null,
          seats: null,
          billing_source: "manual",
        }}
      />,
    );
    expect(screen.getByText("Starter")).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByText("15 Jan 2027")).toBeInTheDocument();
    expect(screen.getByText("Providers: 1 of 3")).toBeInTheDocument();
  });
});

describe("operator nav", () => {
  it("marks the active section", () => {
    expect(isOperatorLinkActive("/operator", "/operator")).toBe(true);
    expect(isOperatorLinkActive("/operator/customers/x", "/operator")).toBe(
      false,
    );
    expect(
      isOperatorLinkActive("/operator/customers/x", "/operator/customers"),
    ).toBe(true);
  });
});

describe("PlanStateInitializer", () => {
  it("hands the plan to the sidebar store after mount", () => {
    render(<PlanStateInitializer features={["reports"]} isOperator />);
    expect(usePlanStore.getState()).toMatchObject({
      features: ["reports"],
      isOperator: true,
    });
    usePlanStore.getState().setPlanState(null, false);
  });
});
