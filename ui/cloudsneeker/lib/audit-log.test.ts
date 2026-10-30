import { describe, expect, it } from "vitest";

import { AUDIT_LOG_EXPORT_API, PRODUCT_ROUTE } from "@/cloudsneeker/routes";

import {
  AUDIT_CATEGORY_OPTIONS,
  AUDIT_PAGE_SIZE,
  auditActionLabel,
  auditExportHref,
  auditExportUpstreamQuery,
  auditFilterParams,
  auditListParams,
  auditOutcomeLabel,
  auditOutcomeVariant,
  auditPageHref,
  auditTargetTypeLabel,
  formatAuditTime,
  parseAuditLogFilters,
  shortId,
} from "./audit-log";

describe("auditActionLabel", () => {
  it("labels recorded actions for people", () => {
    expect(auditActionLabel("auth.sign_in")).toBe("Signed in");
    expect(auditActionLabel("auth.sign_in_failed")).toBe("Sign-in failed");
    expect(auditActionLabel("provider.delete")).toBe("Deleted provider");
    expect(auditActionLabel("provider_secret.update")).toBe(
      "Updated provider credentials",
    );
    expect(auditActionLabel("report.share_link.revoke")).toBe(
      "Revoked report share link",
    );
    expect(auditActionLabel("scan.launch")).toBe("Launched scan");
    expect(auditActionLabel("user.roles.add")).toBe("Added user roles");
  });

  it("never shows engine names", () => {
    for (const action of [
      "trivy_target.create",
      "trivy_run.cancel",
      "custodian_policy.delete",
      "custodian_run.create",
    ]) {
      expect(auditActionLabel(action)).not.toMatch(/trivy|custodian/i);
    }
    for (const option of AUDIT_CATEGORY_OPTIONS) {
      expect(option.label).not.toMatch(/trivy|custodian|prowler/i);
    }
  });

  it("keeps unknown actions readable", () => {
    expect(auditActionLabel("new_thing.create")).toBe("Created new thing");
    expect(auditActionLabel("widget.frobnicate")).toBe("Widget: frobnicate");
    expect(auditActionLabel("solo")).toBe("Solo");
    expect(auditActionLabel("")).toBe("Unknown action");
  });
});

describe("audit labels", () => {
  it("maps outcomes and target types", () => {
    expect(auditOutcomeLabel("success")).toBe("Success");
    expect(auditOutcomeLabel("failure")).toBe("Failure");
    expect(auditOutcomeLabel("other")).toBe("Unknown");
    expect(auditOutcomeVariant("success")).toBe("success");
    expect(auditOutcomeVariant("failure")).toBe("error");
    expect(auditTargetTypeLabel("provider_secret")).toBe(
      "Provider credentials",
    );
    expect(auditTargetTypeLabel("mystery_type")).toBe("Mystery type");
  });

  it("formats times in UTC and keeps bad input", () => {
    expect(formatAuditTime("2026-10-30T09:15:00Z")).toContain("2026");
    expect(formatAuditTime("2026-10-30T09:15:00Z")).toContain("09:15:00");
    expect(formatAuditTime("nope")).toBe("nope");
    expect(shortId("22222222-2222-4222-8222-222222222222")).toBe("22222222…");
    expect(shortId("abc")).toBe("abc");
  });
});

describe("audit filters", () => {
  it("parses and validates page search params", () => {
    expect(
      parseAuditLogFilters({
        category: "auth",
        actor: "  a@example.com ",
        outcome: "failure",
        from: "2026-10-01",
        to: "2026-10-30",
        page: "3",
      }),
    ).toEqual({
      category: "auth",
      actor: "a@example.com",
      outcome: "failure",
      from: "2026-10-01",
      to: "2026-10-30",
      page: 3,
    });
    expect(
      parseAuditLogFilters({
        category: "drop table",
        outcome: "maybe",
        from: "yesterday",
        page: "-1",
      }),
    ).toEqual({ page: 1 });
    expect(parseAuditLogFilters({ category: ["role", "user"] })).toEqual({
      category: "role",
      page: 1,
    });
  });

  it("builds API list params", () => {
    const filters = parseAuditLogFilters({
      category: "role",
      actor: "b@example.com",
      from: "2026-10-01",
      page: "2",
    });
    expect(auditFilterParams(filters)).toEqual({
      "filter[action__startswith]": "role.",
      "filter[actor]": "b@example.com",
      "filter[inserted_at__gte]": "2026-10-01",
    });
    expect(auditListParams(filters)).toMatchObject({
      sort: "-inserted_at",
      "page[size]": String(AUDIT_PAGE_SIZE),
      "page[number]": "2",
    });
  });

  it("builds export and page links with the same filters", () => {
    const filters = parseAuditLogFilters({
      outcome: "failure",
      to: "2026-10-30",
    });
    const href = auditExportHref(filters);
    expect(href.startsWith(`${AUDIT_LOG_EXPORT_API}?`)).toBe(true);
    const query = new URL(href, "https://ui.example").searchParams;
    expect(query.get("format")).toBe("csv");
    expect(query.get("filter[outcome]")).toBe("failure");
    expect(query.get("filter[inserted_at__lte]")).toBe("2026-10-30");

    expect(auditPageHref(filters, 1)).toBe(
      `${PRODUCT_ROUTE.AUDIT_LOG}?outcome=failure&to=2026-10-30`,
    );
    expect(auditPageHref(parseAuditLogFilters({}), 2)).toBe(
      `${PRODUCT_ROUTE.AUDIT_LOG}?page=2`,
    );
    expect(auditPageHref(parseAuditLogFilters({}), 1)).toBe(
      PRODUCT_ROUTE.AUDIT_LOG,
    );
  });

  it("forwards only allow-listed params to the export API", () => {
    const incoming = new URLSearchParams({
      "filter[action__startswith]": "auth.",
      "filter[tenant]": "other",
      "page[size]": "999999",
      evil: "1",
    });
    const query = new URLSearchParams(auditExportUpstreamQuery(incoming));
    expect(Object.fromEntries(query)).toEqual({
      format: "csv",
      "filter[action__startswith]": "auth.",
    });
  });
});
