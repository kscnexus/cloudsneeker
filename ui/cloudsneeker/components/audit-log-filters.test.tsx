import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import {
  AUDIT_PARAM,
  parseAuditLogFilters,
} from "@/cloudsneeker/lib/audit-log";
import { AUDIT_LOG_EXPORT_API } from "@/cloudsneeker/routes";

const navigation = vi.hoisted(() => ({
  router: { push: () => undefined },
  params: new URLSearchParams("filter[outcome]=failure"),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => navigation.router,
  usePathname: () => "/settings/audit-log",
  useSearchParams: () => navigation.params,
}));

import { AuditLogFilters } from "./audit-log-filters";

describe("AuditLogFilters", () => {
  it("shows the standard filter bar with the applied outcome", () => {
    render(
      <AuditLogFilters
        filters={parseAuditLogFilters({ [AUDIT_PARAM.OUTCOME]: "failure" })}
      />,
    );

    expect(screen.getByText("All Actions")).toBeInTheDocument();
    expect(
      screen.getByPlaceholderText("Actor email (press Enter)"),
    ).toBeInTheDocument();
    // The applied filter shows as a removable chip.
    expect(screen.getAllByText(/Failure/).length).toBeGreaterThan(0);
  });

  it("reads the filter bar names and the earlier ones", () => {
    expect(
      parseAuditLogFilters({
        [AUDIT_PARAM.CATEGORY]: "auth",
        [AUDIT_PARAM.SEARCH]: "a@example.com",
        from: "2026-10-01",
      }),
    ).toMatchObject({
      category: "auth",
      actor: "a@example.com",
      from: "2026-10-01",
    });
  });

  it("links the CSV export with the same filters", () => {
    render(
      <AuditLogFilters
        filters={parseAuditLogFilters({ outcome: "success" })}
      />,
    );

    const link = screen.getByRole("link", { name: /Export CSV/ });
    const href = link.getAttribute("href") ?? "";
    expect(href.startsWith(AUDIT_LOG_EXPORT_API)).toBe(true);
    expect(href).toContain("format=csv");
    expect(href).toContain("filter%5Boutcome%5D=success");
  });
});
