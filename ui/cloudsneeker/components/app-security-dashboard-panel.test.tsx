import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  APP_SECURITY_CATEGORY,
  buildAppSecurityDashboard,
} from "@/cloudsneeker/lib/app-security-dashboard";
import {
  TRIVY_MODE,
  TRIVY_RUN_STATUS,
  TRIVY_RUN_TRIGGER,
} from "@/cloudsneeker/types/trivy";

import { AppSecurityDashboardPanel } from "./app-security-dashboard-panel";

const dashboard = buildAppSecurityDashboard({
  targets: [
    {
      id: "t1",
      type: "trivy-targets",
      attributes: {
        name: "checkout-service",
        description: "",
        mode: TRIVY_MODE.SAST,
        config: {},
        provider_id: "p1",
        schedule_enabled: true,
      },
    },
  ],
  runs: [
    {
      id: "r1",
      type: "trivy-runs",
      attributes: {
        target_id: "t1",
        target_name: "checkout-service",
        provider_id: "p1",
        status: TRIVY_RUN_STATUS.COMPLETED,
        trigger: TRIVY_RUN_TRIGGER.MANUAL,
        scan_id: "scan-1",
        summary: { finding_count: 6 },
        inserted_at: "2026-10-28T09:00:00Z",
      },
    },
  ],
  runTotal: 1,
});

describe("AppSecurityDashboardPanel", () => {
  it("renders KPIs, severity totals and area filters", () => {
    render(
      <AppSecurityDashboardPanel
        dashboard={dashboard}
        activeCategory={null}
        severityTotals={[
          { severity: "critical", count: 2, href: "/findings?c" },
          { severity: "high", count: 4, href: "/findings?h" },
          { severity: "medium", count: 0 },
          { severity: "low", count: 0 },
          { severity: "informational", count: 0 },
        ]}
      />,
    );

    const kpis = screen.getByRole("list", { name: "Key figures" });
    expect(within(kpis).getByText("Targets")).toBeInTheDocument();
    expect(within(kpis).getByText("1 on a schedule")).toBeInTheDocument();
    expect(within(kpis).getByText("6")).toBeInTheDocument();
    expect(
      within(kpis).getByText("2 critical in the latest scans"),
    ).toBeInTheDocument();
    expect(within(kpis).getByRole("link", { name: /Last scan/ })).toHaveAttribute(
      "href",
      "/application-security/t1/runs/r1",
    );

    expect(
      screen.getByRole("region", { name: "Open findings by severity" }),
    ).toBeInTheDocument();

    const areas = screen.getByRole("list", { name: "Areas" });
    expect(within(areas).getAllByRole("link")).toHaveLength(7);
    expect(
      within(areas).getByRole("link", { name: /Code \(SAST\)/ }),
    ).toHaveAttribute("href", "/application-security?category=code");
    expect(
      within(areas).getByText("6 findings in the latest scans"),
    ).toBeInTheDocument();
  });

  it("links the active area back to all targets", () => {
    render(
      <AppSecurityDashboardPanel
        dashboard={dashboard}
        activeCategory={APP_SECURITY_CATEGORY.CODE}
        severityTotals={null}
      />,
    );

    const active = screen.getByRole("link", { name: /Code \(SAST\)/ });
    expect(active).toHaveAttribute("href", "/application-security");
    expect(active).toHaveAttribute("aria-current", "true");
    expect(
      screen.queryByRole("region", { name: "Open findings by severity" }),
    ).not.toBeInTheDocument();
  });
});
