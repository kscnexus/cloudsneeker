import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { CUSTODIAN_RUN_STATUS } from "@/cloudsneeker/types/custodian";

import { CustodianDashboardPanel } from "./custodian-dashboard-panel";

describe("CustodianDashboardPanel", () => {
  it("renders metric cards and recent activity", () => {
    render(
      <CustodianDashboardPanel
        metrics={{
          policyCount: 2,
          scheduledPolicyCount: 1,
          runCount: 3,
          completedRunCount: 1,
          failedRunCount: 1,
          activeRunCount: 1,
          resourcesMatched: 12,
          recentRuns: [
            {
              runId: "run-1",
              policyId: "policy-1",
              policyName: "unused-ebs",
              status: CUSTODIAN_RUN_STATUS.COMPLETED,
              trigger: "manual",
              resourcesMatched: 12,
              insertedAt: "2026-03-01T10:00:00Z",
              error: "",
            },
          ],
          topPolicies: [
            {
              policyId: "policy-1",
              policyName: "unused-ebs",
              runCount: 2,
              resourcesMatched: 12,
              providerLabel: "Prod",
            },
          ],
        }}
      />,
    );

    expect(screen.getByText("Policies")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.getByText("Resources matched")).toBeInTheDocument();
    expect(screen.getAllByText("12")).toHaveLength(2);
    expect(screen.getByText("Recent dry-runs")).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "unused-ebs" })[0]).toHaveAttribute(
      "href",
      "/custodian/policy-1/runs/run-1",
    );
    expect(screen.getByText("Top policies by resources")).toBeInTheDocument();
  });
});
