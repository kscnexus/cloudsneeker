import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { CUSTODIAN_RUN_STATUS } from "@/cloudsneeker/types/custodian";

import { CustodianReportsTable } from "./custodian-reports-table";

describe("CustodianReportsTable", () => {
  it("renders report rows with policy links and durations", () => {
    render(
      <CustodianReportsTable
        rows={[
          {
            runId: "run-1",
            policyId: "policy-1",
            policyName: "unused-ebs",
            providerLabel: "Prod",
            status: CUSTODIAN_RUN_STATUS.COMPLETED,
            trigger: "scheduled",
            resourcesMatched: 4,
            startedAt: "2026-03-01T10:00:00Z",
            finishedAt: "2026-03-01T10:00:30Z",
            durationMs: 30_000,
            error: "",
            insertedAt: "2026-03-01T10:00:00Z",
          },
        ]}
      />,
    );

    expect(screen.getByRole("link", { name: "unused-ebs" })).toHaveAttribute(
      "href",
      "/custodian/policy-1",
    );
    expect(screen.getByText("Prod")).toBeInTheDocument();
    expect(screen.getByText("completed")).toBeInTheDocument();
    expect(screen.getByText("scheduled")).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();
    expect(screen.getByText("30s")).toBeInTheDocument();
  });

  it("shows an empty message when there are no rows", () => {
    render(<CustodianReportsTable rows={[]} />);
    expect(
      screen.getByText(/No Custodian dry-run reports yet/i),
    ).toBeInTheDocument();
  });
});
