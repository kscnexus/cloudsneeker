import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { LibraryPolicyAttributes } from "@/cloudsneeker/types/custodian-library";

import { CustodianLibraryBrowser } from "./custodian-library-browser";

const { installMock, refreshMock } = vi.hoisted(() => ({
  installMock: vi.fn(),
  refreshMock: vi.fn(),
}));

vi.mock("@/cloudsneeker/actions/custodian-library", () => ({
  installCustodianLibraryPolicies: installMock,
}));

const searchParams = vi.hoisted(() => new URLSearchParams());

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), refresh: refreshMock }),
  usePathname: () => "/governance/library",
  useSearchParams: () => searchParams,
}));

const policy = (
  overrides: Partial<LibraryPolicyAttributes>,
): LibraryPolicyAttributes => ({
  id: "aws-sg-ssh-open",
  name: "SSH open to the internet",
  description: "Security groups allowing port 22 from 0.0.0.0/0.",
  provider_type: "aws",
  category: "network",
  category_name: "Network",
  severity: "high",
  resource: "aws.security-group",
  frameworks: ["CIS"],
  starter: true,
  policy_yaml:
    "policies:\n- name: aws-sg-ssh-open\n  resource: aws.security-group\n",
  installed: false,
  ...overrides,
});

const POLICIES = [
  policy({}),
  policy({
    id: "aws-ebs-unattached",
    name: "Unattached EBS volumes",
    description: "EBS volumes not attached to any instance.",
    category: "cost",
    category_name: "Cost optimization",
    severity: "low",
    resource: "aws.ebs",
    frameworks: ["FinOps"],
    installed: true,
  }),
];

const renderBrowser = (providers = [{ id: "p1", label: "prod" }]) =>
  render(
    <CustodianLibraryBrowser
      providerType="aws"
      policies={POLICIES}
      categories={[
        { id: "network", name: "Network", description: "" },
        { id: "cost", name: "Cost optimization", description: "" },
      ]}
      coverage={[
        {
          provider_type: "aws",
          category: "network",
          category_name: "Network",
          total: 1,
          active: 0,
        },
        {
          provider_type: "aws",
          category: "cost",
          category_name: "Cost optimization",
          total: 1,
          active: 1,
        },
      ]}
      providers={providers}
    />,
  );

describe("CustodianLibraryBrowser", () => {
  beforeEach(() => {
    installMock.mockReset();
    refreshMock.mockReset();
  });

  it("lists policies with coverage and marks added ones", () => {
    renderBrowser();
    expect(screen.getAllByTestId("library-policy")).toHaveLength(2);
    expect(
      screen.getByText(/1 of 2 library policies active/),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Added/ })).toBeDisabled();
    expect(screen.getByRole("link", { name: "Azure" })).toHaveAttribute(
      "href",
      "/governance/library?provider=azure",
    );
  });

  it("searches and filters by category card", async () => {
    const user = userEvent.setup();
    renderBrowser();
    await user.type(screen.getByLabelText("Search the library"), "ebs");
    expect(screen.getAllByTestId("library-policy")).toHaveLength(1);
    expect(screen.getByText("Unattached EBS volumes")).toBeInTheDocument();

    await user.clear(screen.getByLabelText("Search the library"));
    await user.click(screen.getByRole("button", { name: /^Network/ }));
    expect(screen.getAllByTestId("library-policy")).toHaveLength(1);
    expect(screen.getByText("SSH open to the internet")).toBeInTheDocument();
  });

  it("previews the YAML", async () => {
    const user = userEvent.setup();
    renderBrowser();
    await user.click(screen.getAllByRole("button", { name: /YAML/ })[0]);
    expect(screen.getByText(/name: aws-sg-ssh-open/)).toBeInTheDocument();
  });

  it("adds a policy to the selected provider in one click", async () => {
    installMock.mockResolvedValue({
      data: [],
      meta: { created: 1, skipped: [] },
    });
    const user = userEvent.setup();
    renderBrowser();
    await user.click(screen.getByRole("button", { name: /^Add$/ }));
    expect(installMock).toHaveBeenCalledWith({
      providerId: "p1",
      policyIds: ["aws-sg-ssh-open"],
    });
    expect(await screen.findByText("Added 1 policy.")).toBeInTheDocument();
    expect(refreshMock).toHaveBeenCalled();
  });

  it("adds the remaining starter pack", async () => {
    installMock.mockResolvedValue({
      data: [],
      meta: { created: 1, skipped: [] },
    });
    const user = userEvent.setup();
    renderBrowser();
    await user.click(
      screen.getByRole("button", { name: /Add starter pack \(1\)/ }),
    );
    expect(installMock).toHaveBeenCalledWith({
      providerId: "p1",
      policyIds: ["aws-sg-ssh-open"],
    });
  });

  it("shows install errors", async () => {
    installMock.mockResolvedValue({
      error: "Unknown provider ID for this tenant.",
    });
    const user = userEvent.setup();
    renderBrowser();
    await user.click(screen.getByRole("button", { name: /^Add$/ }));
    expect(
      await screen.findByText("Unknown provider ID for this tenant."),
    ).toBeInTheDocument();
  });

  it("disables adding without a connected provider", () => {
    renderBrowser([]);
    expect(screen.getByRole("button", { name: /^Add$/ })).toBeDisabled();
    expect(screen.getByText("No AWS provider connected")).toBeInTheDocument();
  });

  it("never names the engine", () => {
    const { container } = renderBrowser();
    expect(container.textContent).not.toMatch(/Custodian|Trivy|Prowler/);
  });
});
