import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { AreaFindingAttributes } from "@/cloudsneeker/types/area-findings";

vi.mock("@/cloudsneeker/components/mute-findings-button", () => ({
  MuteFindingsButton: ({ findingUids }: { findingUids: string[] }) => (
    <button type="button">{`mute:${findingUids.join(",")}`}</button>
  ),
}));

import { GovernanceFindingDetail } from "./governance-finding-detail";

const finding = (
  overrides: Partial<AreaFindingAttributes> = {},
): AreaFindingAttributes =>
  ({
    uid: "custodian-p1-vol-1",
    finding_id: null,
    area: "governance",
    title: "Unattached EBS volume",
    severity: "high",
    status: "FAIL",
    muted: false,
    check_id: "unused-ebs",
    description: "Volumes not attached to an instance.",
    resource_id: "vol-1",
    resource_name: "scratch",
    resource_type: "aws.ebs",
    region: "eu-west-1",
    source_kind: "policy",
    source_id: "p1",
    source_name: "Unused volumes",
    provider_id: "prov-1",
    run_id: "run-9",
    first_seen_at: "2026-11-01T08:00:00Z",
    last_seen_at: "2026-11-12T08:00:00Z",
    triage_status: "open",
    triage_notes_count: 0,
    resource_details: { VolumeId: "vol-1", Size: 8 },
    ...overrides,
  }) as AreaFindingAttributes;

describe("GovernanceFindingDetail", () => {
  it("shows the resource, policy, run and resource details", () => {
    render(<GovernanceFindingDetail finding={finding()} canTriage />);

    expect(screen.getByText("Unattached EBS volume")).toBeInTheDocument();
    expect(screen.getByText("scratch")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Unused volumes" }),
    ).toHaveAttribute("href", "/governance/p1");
    expect(
      screen.getByRole("link", { name: "Open the run that reported it" }),
    ).toHaveAttribute("href", "/governance/p1/runs/run-9");
    expect(screen.getByText(/"Size": 8/)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "mute:custodian-p1-vol-1" }),
    ).toBeInTheDocument();
  });

  it("shows the mute reason and no mute action when muted", () => {
    render(
      <GovernanceFindingDetail
        finding={finding({ muted: true, muted_reason: "scratch disk" })}
        canTriage
      />,
    );
    expect(screen.getByText("Muted")).toBeInTheDocument();
    expect(screen.getByText(/scratch disk/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /mute:/ })).toBeNull();
  });

  it("offers no mute action without the manage permission", () => {
    render(<GovernanceFindingDetail finding={finding()} canTriage={false} />);
    expect(screen.queryByRole("button", { name: /mute:/ })).toBeNull();
  });
});
