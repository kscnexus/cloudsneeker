import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  groupRunsByTarget,
  SCANS_PER_TARGET,
} from "@/cloudsneeker/lib/app-security-scan-history";
import {
  TRIVY_RUN_STATUS,
  TRIVY_RUN_TRIGGER,
  type TrivyRunResource,
} from "@/cloudsneeker/types/trivy";

import { AppSecurityRunGroups } from "./app-security-run-groups";

const run = (id: string, targetId: string, day: number): TrivyRunResource => ({
  id,
  type: "cloudsneeker-trivy-runs",
  attributes: {
    target_id: targetId,
    target_name: `acme/${targetId}`,
    target_mode: "repo",
    provider_id: "p1",
    status: day === 30 ? TRIVY_RUN_STATUS.FAILED : TRIVY_RUN_STATUS.COMPLETED,
    trigger: TRIVY_RUN_TRIGGER.MANUAL,
    inserted_at: `2026-10-${String(day).padStart(2, "0")}T10:00:00Z`,
  },
});

describe("AppSecurityRunGroups", () => {
  it("shows one group per target with its scan count and latest status", () => {
    const groups = groupRunsByTarget([
      run("w1", "web", 30),
      run("w2", "web", 29),
      run("a1", "api", 10),
    ]);

    render(<AppSecurityRunGroups groups={groups} />);

    const web = screen.getByText("acme/web").closest("details");
    expect(web).toHaveAttribute("open");
    expect(web).toHaveTextContent("2 scans");
    expect(web).toHaveTextContent("Failed");
    const api = screen.getByText("acme/api").closest("details");
    expect(api).not.toHaveAttribute("open");
    expect(api).toHaveTextContent("1 scan");
    expect(
      screen.getAllByRole("link", { name: "Open target" })[0],
    ).toHaveAttribute("href", "/application-security/web");
  });

  it("says when only the latest scans are shown", () => {
    const runs = Array.from({ length: SCANS_PER_TARGET }, (_, index) =>
      run(`w${index}`, "web", index + 1),
    );

    render(<AppSecurityRunGroups groups={groupRunsByTarget(runs)} />);

    expect(
      screen.getByText(`Latest ${SCANS_PER_TARGET} scans`, { exact: false }),
    ).toBeInTheDocument();
  });

  it("shows the empty message without groups", () => {
    render(<AppSecurityRunGroups groups={[]} emptyMessage="Nothing yet." />);

    expect(screen.getByText("Nothing yet.")).toBeInTheDocument();
  });
});
