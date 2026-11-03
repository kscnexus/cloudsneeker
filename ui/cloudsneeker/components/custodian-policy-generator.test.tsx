import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { CustodianPolicyGenerator } from "./custodian-policy-generator";

const { generateMock, validateMock, createMock, pushMock } = vi.hoisted(() => ({
  generateMock: vi.fn(),
  validateMock: vi.fn(),
  createMock: vi.fn(),
  pushMock: vi.fn(),
}));

vi.mock("@/cloudsneeker/actions/custodian-library", () => ({
  generateCustodianPolicyDraft: generateMock,
  validateCustodianPolicyYaml: validateMock,
}));

vi.mock("@/cloudsneeker/actions/custodian", () => ({
  createCustodianPolicy: createMock,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, refresh: vi.fn() }),
}));

const PROVIDERS = [
  { id: "aws-1", label: "prod", providerType: "aws" as const },
  { id: "gcp-1", label: "data", providerType: "gcp" as const },
];

const DRAFT_YAML =
  "policies:\n- name: unencrypted-ebs\n  resource: aws.ebs\n  filters:\n  - Encrypted: false\n";

const draftResponse = (valid: boolean, error = "") => ({
  data: {
    type: "cloudsneeker-custodian-policy-drafts",
    id: "draft",
    attributes: {
      policy_yaml: DRAFT_YAML,
      name: "unencrypted-ebs",
      description: "Volumes that are not encrypted.",
      resource: "aws.ebs",
      provider_type: "aws",
      valid,
      validation_error: error,
      attempts: 1,
    },
  },
});

const askForDraft = async () => {
  const user = userEvent.setup();
  render(<CustodianPolicyGenerator providers={PROVIDERS} />);
  await user.type(
    screen.getByLabelText(/What should the policy find/),
    "EBS volumes that are not encrypted",
  );
  await user.click(
    screen.getByRole("button", { name: /Generate with Seeker AI/ }),
  );
  return user;
};

describe("CustodianPolicyGenerator", () => {
  beforeEach(() => {
    generateMock.mockReset();
    validateMock.mockReset();
    createMock.mockReset();
    pushMock.mockReset();
  });

  it("needs a description before generating", () => {
    render(<CustodianPolicyGenerator providers={PROVIDERS} />);
    expect(
      screen.getByRole("button", { name: /Generate with Seeker AI/ }),
    ).toBeDisabled();
  });

  it("shows a valid draft for review and saves it", async () => {
    generateMock.mockResolvedValue(draftResponse(true));
    createMock.mockResolvedValue({ data: { id: "policy-9" } });
    const user = await askForDraft();

    expect(generateMock).toHaveBeenCalledWith({
      providerType: "aws",
      prompt: "EBS volumes that are not encrypted",
      resourceType: "",
    });
    expect(
      await screen.findByText("The policy passed validation."),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Policy name")).toHaveValue("Unencrypted ebs");
    expect(screen.getByLabelText("Policy YAML")).toHaveValue(DRAFT_YAML);

    await user.click(screen.getByRole("button", { name: "Save policy" }));
    expect(createMock).toHaveBeenCalledWith({
      name: "Unencrypted ebs",
      description: "Volumes that are not encrypted.",
      policyYaml: DRAFT_YAML,
      providerId: "aws-1",
    });
    expect(pushMock).toHaveBeenCalledWith("/governance/policy-9");
  });

  it("blocks saving an invalid draft until it passes a re-check", async () => {
    generateMock.mockResolvedValue(draftResponse(false, "unknown filter"));
    validateMock.mockResolvedValue({
      data: { attributes: { valid: true, error: "" } },
    });
    const user = await askForDraft();

    expect(
      await screen.findByText(/Validation failed: unknown filter/),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save policy" })).toBeDisabled();

    await user.type(screen.getByLabelText("Policy YAML"), "{Enter}");
    expect(screen.getByText(/The YAML changed/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Check policy" }));

    expect(validateMock).toHaveBeenCalledWith({
      providerType: "aws",
      policyYaml: `${DRAFT_YAML}\n`,
    });
    expect(
      await screen.findByText("The policy passed validation."),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save policy" })).toBeEnabled();
  });

  it("shows why Seeker AI could not draft", async () => {
    generateMock.mockResolvedValue({
      error:
        "Seeker AI is not set up. Add an LLM provider in Seeker AI settings first.",
    });
    await askForDraft();
    expect(
      await screen.findByText(/Seeker AI is not set up/),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText("Policy YAML")).not.toBeInTheDocument();
  });

  it("only offers providers of the chosen cloud", async () => {
    generateMock.mockResolvedValue(draftResponse(true));
    const user = userEvent.setup();
    render(<CustodianPolicyGenerator providers={PROVIDERS} />);
    await user.selectOptions(screen.getByLabelText("Cloud"), "azure");
    await user.type(
      screen.getByLabelText(/What should the policy find/),
      "Storage accounts allowing http",
    );
    await user.click(
      screen.getByRole("button", { name: /Generate with Seeker AI/ }),
    );
    expect(
      await screen.findByText("No Azure provider connected"),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save policy" })).toBeDisabled();
  });
});
