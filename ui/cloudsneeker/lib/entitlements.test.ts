import { describe, expect, it } from "vitest";

import {
  daysUntil,
  featureForHref,
  formatLimit,
  isHrefInPlan,
  limitUsageRows,
  SUBSCRIPTION_BANNER_TONE,
  subscriptionBanner,
} from "./entitlements";

const NOW = new Date("2026-11-01T12:00:00Z");

const entitlements = (
  overrides: Partial<Parameters<typeof subscriptionBanner>[0]> = {},
): Parameters<typeof subscriptionBanner>[0] => ({
  effective_status: "active",
  read_only: false,
  trial_ends_at: null,
  ends_at: null,
  plan: { code: "starter", name: "Starter" },
  ...overrides,
});

describe("featureForHref", () => {
  it.each([
    ["/attack-paths", "attack_paths"],
    ["/attack-paths/query-builder", "attack_paths"],
    ["/compliance?scanId=1", "compliance"],
    ["/application-security/new", "application_security"],
    ["/governance", "governance"],
    ["/reports/run-1", "reports"],
    ["/triage", "finding_triage"],
    ["/settings/audit-log", "audit_log"],
    ["/lighthouse", "seeker_ai"],
    ["/lighthouse/settings", "seeker_ai"],
    ["/integrations/email", "integrations"],
  ])("maps %s to %s", (href, feature) => {
    expect(featureForHref(href)).toBe(feature);
  });

  it.each(["/", "/findings", "/scans", "/providers", "/profile", "/reportsx"])(
    "never gates %s",
    (href) => {
      expect(featureForHref(href)).toBeNull();
    },
  );
});

describe("isHrefInPlan", () => {
  it("keeps everything while the plan is unknown", () => {
    expect(isHrefInPlan("/attack-paths", null)).toBe(true);
  });

  it("checks the feature list", () => {
    expect(isHrefInPlan("/attack-paths", ["compliance"])).toBe(false);
    expect(isHrefInPlan("/compliance", ["compliance"])).toBe(true);
    expect(isHrefInPlan("/findings", [])).toBe(true);
  });
});

describe("subscriptionBanner", () => {
  it("is empty for an active plan without an end date", () => {
    expect(subscriptionBanner(entitlements(), NOW)).toBeNull();
  });

  it.each(["suspended", "expired", "cancelled"] as const)(
    "warns that a %s organization is read-only",
    (status) => {
      const banner = subscriptionBanner(
        entitlements({ effective_status: status, read_only: true }),
        NOW,
      );
      expect(banner?.tone).toBe(SUBSCRIPTION_BANNER_TONE.DANGER);
      expect(banner?.title.toLowerCase()).toContain(status);
      expect(banner?.message).toContain("view your data");
    },
  );

  it("warns when a trial ends within 7 days", () => {
    const banner = subscriptionBanner(
      entitlements({
        effective_status: "trial",
        trial_ends_at: "2026-11-04T12:00:00Z",
      }),
      NOW,
    );
    expect(banner?.tone).toBe(SUBSCRIPTION_BANNER_TONE.WARNING);
    expect(banner?.title).toBe("Your trial ends in 3 days");
  });

  it("warns when a paid plan ends within 7 days", () => {
    const banner = subscriptionBanner(
      entitlements({ ends_at: "2026-11-02T10:00:00Z" }),
      NOW,
    );
    expect(banner?.title).toBe("Your Starter plan ends in 1 day");
  });

  it("stays quiet for later end dates", () => {
    expect(
      subscriptionBanner(
        entitlements({
          effective_status: "trial",
          trial_ends_at: "2026-12-01T00:00:00Z",
        }),
        NOW,
      ),
    ).toBeNull();
  });
});

describe("daysUntil", () => {
  it("rounds up and handles missing values", () => {
    expect(daysUntil("2026-11-02T13:00:00Z", NOW)).toBe(2);
    expect(daysUntil("2026-10-30T12:00:00Z", NOW)).toBe(-2);
    expect(daysUntil(null, NOW)).toBeNull();
    expect(daysUntil("not a date", NOW)).toBeNull();
  });
});

describe("limitUsageRows", () => {
  it("reports usage against each limit", () => {
    const rows = limitUsageRows(
      {
        providers: 4,
        users: 2,
        scans_this_month: 10,
        seeker_ai_requests_this_month: null,
      },
      {
        providers: 3,
        users: 5,
        scans_per_month: null,
        application_security_targets: 0,
      },
    );
    const byKey = Object.fromEntries(rows.map((row) => [row.key, row]));
    expect(byKey.providers).toMatchObject({
      used: 4,
      limit: 3,
      ratio: 1,
      over: true,
    });
    expect(byKey.users).toMatchObject({
      used: 2,
      limit: 5,
      ratio: 0.4,
      over: false,
    });
    expect(byKey.scans_per_month).toMatchObject({ limit: null, ratio: null });
    expect(byKey.application_security_targets).toMatchObject({
      used: null,
      ratio: null,
    });
    expect(byKey.seeker_ai_requests_per_month.used).toBeNull();
  });

  it("formats limits", () => {
    expect(formatLimit(null)).toBe("Unlimited");
    expect(formatLimit(1500)).toBe("1,500");
  });
});
