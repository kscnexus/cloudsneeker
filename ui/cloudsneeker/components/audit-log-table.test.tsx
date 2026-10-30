import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  AUDIT_EVENT_RESOURCE_TYPE,
  type AuditEventResource,
} from "@/cloudsneeker/types/audit";

import { AUDIT_LOG_COLUMNS, AuditLogTable } from "./audit-log-table";

const event = (
  id: string,
  attributes: Partial<AuditEventResource["attributes"]>,
): AuditEventResource => ({
  type: AUDIT_EVENT_RESOURCE_TYPE,
  id,
  attributes: {
    inserted_at: "2026-10-30T09:15:00Z",
    actor_id: null,
    actor_email: "",
    action: "role.create",
    target_type: "",
    target_id: "",
    target_label: "",
    outcome: "success",
    status_code: 201,
    ip_address: null,
    user_agent: "",
    request_id: "",
    method: "POST",
    path: "/api/v1/roles",
    metadata: {},
    ...attributes,
  },
});

describe("AuditLogTable", () => {
  it("renders the columns and one row per event", () => {
    render(
      <AuditLogTable
        events={[
          event("1", {
            actor_email: "admin@example.com",
            action: "provider.delete",
            target_type: "provider",
            target_label: "prod-account",
            ip_address: "203.0.113.7",
          }),
          event("2", {
            action: "auth.sign_in_failed",
            outcome: "failure",
            target_type: "user",
            target_id: "22222222-2222-4222-8222-222222222222",
          }),
        ]}
      />,
    );

    for (const header of AUDIT_LOG_COLUMNS) {
      expect(
        screen.getByRole("columnheader", { name: header }),
      ).toBeInTheDocument();
    }
    const rows = screen.getAllByTestId("audit-log-row");
    expect(rows).toHaveLength(2);

    const first = within(rows[0]);
    expect(first.getByText("admin@example.com")).toBeInTheDocument();
    expect(first.getByText("Deleted provider")).toBeInTheDocument();
    expect(first.getByText("Provider · prod-account")).toBeInTheDocument();
    expect(first.getByText("Success")).toBeInTheDocument();
    expect(first.getByText("203.0.113.7")).toBeInTheDocument();

    const second = within(rows[1]);
    expect(second.getByText("Unknown")).toBeInTheDocument();
    expect(second.getByText("Sign-in failed")).toBeInTheDocument();
    expect(second.getByText("User · 22222222…")).toBeInTheDocument();
    expect(second.getByText("Failure")).toBeInTheDocument();
  });

  it("never shows engine names from action strings", () => {
    const { container } = render(
      <AuditLogTable
        events={[
          event("1", {
            action: "trivy_target.create",
            target_type: "trivy_target",
          }),
          event("2", {
            action: "custodian_policy.update",
            target_type: "custodian_policy",
          }),
        ]}
      />,
    );
    expect(container.textContent).not.toMatch(/trivy|custodian/i);
  });
});
