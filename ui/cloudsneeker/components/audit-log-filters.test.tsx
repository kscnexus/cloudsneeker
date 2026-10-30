import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { parseAuditLogFilters } from "@/cloudsneeker/lib/audit-log";
import { AUDIT_LOG_EXPORT_API, PRODUCT_ROUTE } from "@/cloudsneeker/routes";

import { AuditLogFilters } from "./audit-log-filters";

describe("AuditLogFilters", () => {
  it("submits to the audit log page with the current values", () => {
    render(
      <AuditLogFilters
        filters={parseAuditLogFilters({
          category: "auth",
          actor: "a@example.com",
          outcome: "failure",
          from: "2026-10-01",
        })}
      />,
    );

    const form = screen.getByRole("form", { name: "Audit log filters" });
    expect(form).toHaveAttribute("method", "get");
    expect(form).toHaveAttribute("action", PRODUCT_ROUTE.AUDIT_LOG);
    expect(screen.getByLabelText("Action")).toHaveValue("auth");
    expect(screen.getByLabelText("Actor email")).toHaveValue("a@example.com");
    expect(screen.getByLabelText("Outcome")).toHaveValue("failure");
    expect(screen.getByLabelText("From")).toHaveValue("2026-10-01");
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
