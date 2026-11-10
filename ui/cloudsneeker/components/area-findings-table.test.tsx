import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AREA_CONFIG } from "@/cloudsneeker/lib/area-findings";
import type { AreaFindingResource } from "@/cloudsneeker/types/area-findings";

import { AreaFindingsTable } from "./area-findings-table";

const { bulkMock, updateMock, refreshMock } = vi.hoisted(() => ({
  bulkMock: vi.fn(),
  updateMock: vi.fn(),
  refreshMock: vi.fn(),
}));

vi.mock("@/cloudsneeker/actions/finding-triage", () => ({
  bulkUpdateFindingTriage: bulkMock,
  updateFindingTriage: updateMock,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: refreshMock }),
}));

const finding = (
  uid: string,
  overrides: Partial<AreaFindingResource["attributes"]> = {},
): AreaFindingResource => ({
  id: uid,
  type: "cloudsneeker-area-findings",
  attributes: {
    uid,
    finding_id: `id-${uid}`,
    area: "application_security",
    title: `Title ${uid}`,
    severity: "high",
    status: "FAIL",
    muted: false,
    check_id: "CVE-2026-1",
    description: "Prototype pollution",
    status_extended: "",
    remediation: "Upgrade lodash",
    fix_available: false,
    fix_summary: "",
    installed_version: "",
    fixed_version: "",
    fix_references: [],
    epss_score: null,
    epss_percentile: null,
    known_exploited: false,
    kev_date_added: null,
    kev_due_date: null,
    kev_ransomware: false,
    kev_required_action: "",
    resource_id: "package.json:lodash",
    resource_name: "lodash",
    resource_type: "npm",
    location: "lodash 4.17.0",
    region: "",
    service: "",
    source_kind: "target",
    source_id: "target-1",
    source_name: "web-repo",
    provider_id: "provider-1",
    first_seen_at: "2026-10-01T10:00:00Z",
    last_seen_at: "2026-11-01T10:00:00Z",
    categories: ["CWE-1321"],
    triage_id: null,
    triage_status: "open",
    triage_notes_count: 0,
    triage_latest_note: "",
    assignee_id: null,
    ...overrides,
  },
});

const config = AREA_CONFIG.application_security;

describe("AreaFindingsTable", () => {
  beforeEach(() => {
    bulkMock.mockReset().mockResolvedValue({ data: {} });
    updateMock.mockReset().mockResolvedValue({ data: {} });
    refreshMock.mockReset();
  });

  it("shows the area's columns and finding fields", () => {
    render(
      <AreaFindingsTable config={config} findings={[finding("a")]} canTriage />,
    );

    for (const header of ["Rule or CVE", "Package or file", "Target"]) {
      expect(
        screen.getByRole("columnheader", { name: header }),
      ).toBeInTheDocument();
    }
    expect(screen.getByText("Title a")).toBeInTheDocument();
    expect(screen.getByText("lodash 4.17.0")).toBeInTheDocument();
    expect(screen.getByText("web-repo")).toBeInTheDocument();
  });

  it("is read only without the manage permission", () => {
    render(
      <AreaFindingsTable
        config={config}
        findings={[finding("a", { triage_status: "remediating" })]}
        canTriage={false}
      />,
    );

    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
    expect(screen.getByText("Remediating")).toBeInTheDocument();
  });

  it("sets one status on the selected findings", async () => {
    const user = userEvent.setup();
    render(
      <AreaFindingsTable
        config={config}
        findings={[finding("a"), finding("b")]}
        canTriage
      />,
    );

    await user.click(
      screen.getByRole("checkbox", {
        name: "Select all findings on this page",
      }),
    );
    expect(screen.getByText("2 selected")).toBeInTheDocument();
    await user.selectOptions(
      screen.getByLabelText("Triage status for the selected findings"),
      "false_positive",
    );
    await user.click(screen.getByRole("button", { name: "Set status" }));

    await waitFor(() =>
      expect(bulkMock).toHaveBeenCalledWith(["a", "b"], "false_positive"),
    );
    await waitFor(() => expect(refreshMock).toHaveBeenCalled());
  });

  it("changes the status of one finding and shows API errors", async () => {
    updateMock.mockResolvedValue({ error: "Forbidden" });
    const user = userEvent.setup();
    render(
      <AreaFindingsTable config={config} findings={[finding("a")]} canTriage />,
    );

    await user.selectOptions(
      screen.getByLabelText("Triage status of Title a"),
      "resolved",
    );

    await waitFor(() =>
      expect(updateMock).toHaveBeenCalledWith("a", { status: "resolved" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent("Forbidden");
    expect(refreshMock).not.toHaveBeenCalled();
  });

  it("expands a finding to show details and add a note", async () => {
    const user = userEvent.setup();
    render(
      <AreaFindingsTable config={config} findings={[finding("a")]} canTriage />,
    );

    await user.click(screen.getByRole("button", { name: /Title a/ }));
    expect(screen.getByText("Upgrade lodash")).toBeInTheDocument();
    expect(screen.getByText("CWE-1321")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Add a note"), "Bumping in PR 12");
    await user.click(screen.getByRole("button", { name: "Save note" }));

    await waitFor(() =>
      expect(updateMock).toHaveBeenCalledWith("a", {
        note: "Bumping in PR 12",
      }),
    );
  });

  it("shows the fix column and how to fix the finding", async () => {
    const user = userEvent.setup();
    render(
      <AreaFindingsTable
        config={config}
        findings={[
          finding("a", {
            fix_available: true,
            fix_summary: "Upgrade lodash from 4.17.0 to 4.17.21 or later.",
            installed_version: "4.17.0",
            fixed_version: "4.17.21",
            fix_references: ["https://github.com/advisories/GHSA-1"],
          }),
          finding("b", {
            fix_summary: "No fixed version of left-pad is published yet.",
          }),
        ]}
        canTriage
      />,
    );

    expect(
      screen.getByRole("columnheader", { name: "Fix" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Upgrade to 4.17.21")).toBeInTheDocument();
    expect(screen.getByText("No fix yet")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Title a/ }));
    expect(screen.getByText("How to fix")).toBeInTheDocument();
    expect(
      screen.getByText("Upgrade lodash from 4.17.0 to 4.17.21 or later."),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /github\.com/ })).toHaveAttribute(
      "href",
      "https://github.com/advisories/GHSA-1",
    );
  });

  it("flags known exploited CVEs and shows exploit details", async () => {
    const user = userEvent.setup();
    render(
      <AreaFindingsTable
        config={config}
        findings={[
          finding("a", {
            known_exploited: true,
            kev_ransomware: true,
            kev_date_added: "2021-12-10",
            kev_due_date: "2021-12-24",
            kev_required_action: "Apply updates per vendor instructions.",
            epss_score: 0.94358,
            epss_percentile: 0.99962,
          }),
          finding("b", { epss_score: 0.00043, epss_percentile: 0.11 }),
          finding("c"),
        ]}
        canTriage
      />,
    );

    expect(screen.getAllByText("Known exploited")).toHaveLength(1);
    expect(screen.getByText("EPSS 94.4%")).toBeInTheDocument();
    expect(screen.getByText("EPSS 0.04%")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Title a/ }));
    expect(screen.getByText("Exploitation")).toBeInTheDocument();
    expect(
      screen.getByText(
        /Known Exploited Vulnerabilities catalog since 2021-12-10/,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Used in ransomware campaigns/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Required action: Apply updates/),
    ).toBeInTheDocument();
  });

  it("has no fix column for governance findings", () => {
    render(
      <AreaFindingsTable
        config={AREA_CONFIG.governance}
        findings={[finding("a", { area: "governance" })]}
        canTriage
      />,
    );

    expect(
      screen.queryByRole("columnheader", { name: "Fix" }),
    ).not.toBeInTheDocument();
  });
});
