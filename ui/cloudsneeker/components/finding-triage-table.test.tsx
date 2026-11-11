import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { FindingTriageResource } from "@/cloudsneeker/types/finding-triage";

import { FindingTriageTable } from "./finding-triage-table";

const triage = (
  overrides: Partial<FindingTriageResource["attributes"]> = {},
): FindingTriageResource => ({
  id: "triage-1",
  type: "cloudsneeker-finding-triages",
  attributes: {
    finding_uid: "aws-s3_bucket_public-123-us-east-1-bucket",
    finding_id: "finding-1",
    status: "reopened",
    stored_status: "resolved",
    status_changed_at: "2026-10-01T10:00:00Z",
    updated_at: "2026-10-01T10:00:00Z",
    source: "manual",
    check_id: "s3_bucket_public",
    provider_id: "provider-1",
    assignee_id: null,
    updated_by_id: "user-1",
    raw_finding_status: "FAIL",
    triage_notes_count: 3,
    has_note: true,
    note_id: "note-1",
    current_note: "Fixed in terraform, waiting for apply",
    ...overrides,
  },
});

describe("FindingTriageTable", () => {
  it("shows the status, finding, latest note and a findings link", () => {
    render(<FindingTriageTable triages={[triage()]} />);

    expect(screen.getByText("Reopened")).toBeInTheDocument();
    expect(screen.getByText("s3_bucket_public")).toBeInTheDocument();
    expect(
      screen.getByText("aws-s3_bucket_public-123-us-east-1-bucket"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Fixed in terraform, waiting for apply"),
    ).toBeInTheDocument();
    expect(screen.getByText("3 notes")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /Open in Findings/ }),
    ).toHaveAttribute(
      "href",
      "/findings?filter%5Bcheck_id__in%5D=s3_bucket_public",
    );
  });

  it("shows the expiry, approver and reason of an accepted risk", () => {
    render(
      <FindingTriageTable
        triages={[
          triage({
            status: "risk_accepted",
            stored_status: "risk_accepted",
            risk_expires_on: "2099-01-31",
            risk_reason: "Behind the corporate VPN",
            risk_approved_by_name: "Ada Admin",
          }),
          triage({
            status: "reopened",
            stored_status: "reopened",
            risk_expires_on: "2026-10-31",
            risk_expired_at: "2026-11-01T00:00:00Z",
          }),
        ]}
      />,
    );

    expect(screen.getByText("Until 2099-01-31")).toBeInTheDocument();
    expect(screen.getByText("Approved by Ada Admin")).toBeInTheDocument();
    expect(screen.getByText("Behind the corporate VPN")).toBeInTheDocument();
    expect(
      screen.getByText("Risk acceptance expired 2026-10-31"),
    ).toBeInTheDocument();
  });

  it("renders a dash without notes", () => {
    render(
      <FindingTriageTable
        triages={[triage({ current_note: "", triage_notes_count: 0 })]}
      />,
    );

    expect(screen.getByText("—")).toBeInTheDocument();
    expect(screen.queryByText(/notes$/)).not.toBeInTheDocument();
  });
});

describe("FindingTriageTable in another area", () => {
  it("links to the area's findings by UID", () => {
    render(
      <FindingTriageTable
        triages={[triage({ finding_uid: "custodian-p1-vol-1" })]}
        area="governance"
      />,
    );

    expect(
      screen.getByRole("link", { name: /Open in Cloud Governance findings/ }),
    ).toHaveAttribute("href", "/governance/findings?q=custodian-p1-vol-1");
  });
});
