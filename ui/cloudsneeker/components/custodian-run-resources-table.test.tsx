import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { CustodianRunResourcesTable } from "./custodian-run-resources-table";

const RESOURCE = {
  id: "vol-1-0",
  uid: "vol-1",
  name: "orphaned-disk",
  type: "aws.ebs",
  region: "us-east-1",
  service: "ebs",
  policyName: "unused-ebs",
  status: "available",
  tags: { Name: "orphaned-disk" },
  raw: { VolumeId: "vol-1", State: "available" },
};

describe("CustodianRunResourcesTable", () => {
  it("lists matched resources with uid and region", () => {
    render(
      <CustodianRunResourcesTable resources={[RESOURCE]} providerType="aws" />,
    );

    expect(screen.getByText("orphaned-disk")).toBeInTheDocument();
    expect(screen.getByText("vol-1")).toBeInTheDocument();
    expect(screen.getByText("us-east-1")).toBeInTheDocument();
    expect(screen.getByText("aws.ebs")).toBeInTheDocument();
    expect(screen.getByText("available")).toBeInTheDocument();
  });

  it("opens resource details in a sheet", async () => {
    const user = userEvent.setup();
    render(
      <CustodianRunResourcesTable resources={[RESOURCE]} providerType="aws" />,
    );

    await user.click(screen.getByRole("button", { name: "View" }));
    expect(
      screen.getByText(/Matched Custodian resource details/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/"VolumeId": "vol-1"/)).toBeInTheDocument();
  });

  it("shows an empty message when there are no resources", () => {
    render(<CustodianRunResourcesTable resources={[]} />);
    expect(
      screen.getByText(/No resources matched this dry-run/i),
    ).toBeInTheDocument();
  });
});
