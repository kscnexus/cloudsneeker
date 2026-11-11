import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  AREA_FINDING_SORT,
  type AreaFindingFilters,
} from "@/cloudsneeker/lib/area-findings";
import { FINDING_AREA } from "@/cloudsneeker/types/area-findings";

import { RiskPriorityBadge } from "./risk-priority-badge";
import { RiskPriorityFilter } from "./risk-priority-filter";

const filters: AreaFindingFilters = {
  severities: [],
  triage: null,
  source: null,
  search: "",
  sort: AREA_FINDING_SORT.SEVERITY,
  page: 2,
  fix: null,
  priority: "p1",
  application: "prov-1",
};

describe("RiskPriorityFilter", () => {
  it("shows counts and toggles the priority and overdue filters", () => {
    render(
      <RiskPriorityFilter
        area={FINDING_AREA.APPLICATION_SECURITY}
        filters={filters}
        counts={{ p0: 2, p1: 5 }}
        overdueCount={3}
        applicationName="acme/web"
      />,
    );

    const p1 = screen.getByRole("link", { name: /P1 Urgent/ });
    expect(p1).toHaveTextContent("5");
    expect(p1).toHaveAttribute(
      "href",
      "/application-security/findings?app=prov-1",
    );
    expect(screen.getByRole("link", { name: /P0 Immediate/ })).toHaveAttribute(
      "href",
      "/application-security/findings?priority=p0&app=prov-1",
    );
    expect(screen.getByRole("link", { name: /Overdue/ })).toHaveTextContent(
      "3",
    );
    expect(screen.getByText("acme/web")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Show every application" }),
    ).toHaveAttribute("href", "/application-security/findings?priority=p1");
  });
});

describe("RiskPriorityBadge", () => {
  it("labels the priority and flags overdue findings", () => {
    render(<RiskPriorityBadge priority="p0" overdue />);
    expect(screen.getByText("P0 Immediate")).toBeInTheDocument();
    expect(screen.getByText("Overdue")).toBeInTheDocument();
  });

  it("shows a dash without a priority", () => {
    render(<RiskPriorityBadge priority="" />);
    expect(screen.getByText("—")).toBeInTheDocument();
  });
});
