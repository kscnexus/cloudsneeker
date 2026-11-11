import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { AlertEventItem } from "@/cloudsneeker/lib/alert-history";
import { parseListFilters } from "@/cloudsneeker/lib/list-filters";

vi.mock("@/cloudsneeker/components/alert-event-actions", () => ({
  AlertEventActions: ({ status }: { status: string }) => (
    <div>{`actions:${status}`}</div>
  ),
}));

import { AlertHistory } from "./alert-history";

const event: AlertEventItem = {
  id: "e-1",
  ruleId: "r-1",
  ruleName: "Critical code findings",
  trigger: "after_scan",
  insertedAt: "2026-11-12T08:00:00Z",
  total: 5,
  areas: [
    { area: "cloud", label: "Cloud Security", count: 2 },
    { area: "application_security", label: "Application Security", count: 3 },
  ],
  severityCounts: { critical: 1, high: 4 },
  links: ["https://app/application-security/t/runs/r"],
  delivered: true,
  status: "acknowledged",
  statusChange: { at: "2026-11-12T09:00:00Z", by: "Ana" },
  note: "",
};

const pagination = { page: 1, pages: 1, count: 1 };

describe("AlertHistory", () => {
  it("shows the rule, modules, severities, link and status change", () => {
    // When
    render(
      <AlertHistory
        events={[event]}
        filters={parseListFilters({})}
        pagination={pagination}
        loadError={null}
      />,
    );

    // Then
    expect(screen.getByText("Critical code findings")).toBeInTheDocument();
    expect(screen.getByText("Cloud Security: 2")).toBeInTheDocument();
    expect(screen.getByText("Application Security: 3")).toBeInTheDocument();
    expect(screen.getByText("critical 1 · high 4")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Application Security run" }),
    ).toHaveAttribute("href", "https://app/application-security/t/runs/r");
    expect(screen.getByText(/Acknowledged by Ana on/)).toBeInTheDocument();
    expect(screen.getByText("actions:acknowledged")).toBeInTheDocument();
  });

  it("keeps the History tab in the filter form", () => {
    const { container } = render(
      <AlertHistory
        events={[]}
        filters={parseListFilters({})}
        pagination={{ page: 1, pages: 1, count: 0 }}
        loadError={null}
      />,
    );
    expect(
      container.querySelector('input[type="hidden"][name="tab"]'),
    ).toHaveAttribute("value", "history");
    expect(screen.getByText(/No alerts yet/)).toBeInTheDocument();
  });

  it("explains a load failure", () => {
    render(
      <AlertHistory
        events={[]}
        filters={parseListFilters({})}
        pagination={{ page: 1, pages: 1, count: 0 }}
        loadError="Server error"
      />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Alert history could not be loaded. Server error",
    );
  });
});
