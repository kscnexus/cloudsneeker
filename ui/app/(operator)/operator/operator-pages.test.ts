import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const read = (file: string) =>
  readFileSync(path.join(currentDir, file), "utf8");

const PAGES = {
  overview: "page.tsx",
  customers: "customers/page.tsx",
  customer: "customers/[tenantId]/page.tsx",
  newCustomer: "customers/new/page.tsx",
  plans: "plans/page.tsx",
  audit: "audit/page.tsx",
} as const;

describe("operator console", () => {
  it("gates every page behind the operator check", () => {
    const layout = read("layout.tsx");
    expect(layout).toContain("getOperatorMe");
    expect(layout).toContain("OperatorNotAvailable");
    expect(layout).toContain("OperatorShell");
    expect(layout).toContain("index: false");
  });

  it("uses its own root document, not the tenant shell", () => {
    const root = read("../layout.tsx");
    expect(root).toContain('from "../(auth)/layout"');
    expect(root).not.toContain("(prowler)");
  });

  it.each(Object.entries(PAGES))(
    "%s page shows a load error instead of an empty list",
    (_name, file) => {
      const source = read(file);
      expect(source).toContain("OperatorLoadError");
      expect(source).toContain("PageHeader");
    },
  );

  it("loads data through the operator actions", () => {
    expect(read(PAGES.overview)).toContain("listOperatorTenants");
    expect(read(PAGES.customers)).toContain("listOperatorTenants");
    expect(read(PAGES.customer)).toContain("getOperatorTenant");
    expect(read(PAGES.customer)).toContain("SubscriptionEditor");
    expect(read(PAGES.customer)).toContain("UsageBars");
    expect(read(PAGES.plans)).toContain("PlanEditor");
    expect(read(PAGES.audit)).toContain("listOperatorAuditEvents");
  });

  it("only lets the right roles edit", () => {
    expect(read(PAGES.customer)).toContain("MANAGE_SUBSCRIPTIONS");
    expect(read(PAGES.customer)).toContain("SUSPEND_TENANTS");
    expect(read(PAGES.plans)).toContain("MANAGE_PLANS");
    expect(read(PAGES.customers)).toContain("MANAGE_SUBSCRIPTIONS");
    expect(read(PAGES.newCustomer)).toContain("MANAGE_SUBSCRIPTIONS");
  });

  it("creates customers and shows the owner invitation until someone joins", () => {
    expect(read(PAGES.customers)).toContain("OPERATOR_ROUTE.NEW_CUSTOMER");
    expect(read(PAGES.newCustomer)).toContain("CustomerCreateForm");
    expect(read(PAGES.customer)).toContain("AdminInvitationCard");
    expect(read(PAGES.customer)).toContain("members.length === 0");
  });

  it("never names an upstream product or engine", () => {
    for (const file of [...Object.values(PAGES), "layout.tsx"]) {
      expect(read(file)).not.toMatch(/Prowler|Trivy|Custodian/);
    }
  });
});
