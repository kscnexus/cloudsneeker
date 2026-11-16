import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SETUP_GUIDE_INTEGRATION } from "@/cloudsneeker/lib/setup-guides";
import { useProviderWizardStore } from "@/store/provider-wizard/store";

import {
  IntegrationSetupGuideButton,
  ProviderSetupGuideButton,
  SetupGuideButton,
} from "./setup-guide-button";

vi.mock("@/hooks/use-runtime-config", () => ({
  useRuntimeConfig: () => ({ apiBaseUrl: "https://api.example.com/api/v1" }),
}));

const openGuide = async () => {
  await userEvent.click(screen.getByRole("button", { name: "Setup guide" }));
  return screen.findByRole("dialog", { name: "Setup guide" });
};

describe("SetupGuideButton", () => {
  it("renders nothing without a guide", () => {
    const { container } = render(<SetupGuideButton guides={[]} />);

    expect(container).toBeEmptyDOMElement();
  });
});

describe("IntegrationSetupGuideButton", () => {
  it("shows the Slack redirect URL for this site inside the page", async () => {
    render(
      <IntegrationSetupGuideButton
        integration={SETUP_GUIDE_INTEGRATION.SLACK}
      />,
    );

    const dialog = await openGuide();

    expect(
      within(dialog).getByText(
        `${window.location.origin}/integrations/slack/callback`,
      ),
    ).toBeInTheDocument();
    expect(
      within(dialog).getByRole("button", { name: "Copy Redirect URL" }),
    ).toBeInTheDocument();
  });

  it("shows the SAML ACS URL and entity ID", async () => {
    render(
      <IntegrationSetupGuideButton
        integration={SETUP_GUIDE_INTEGRATION.SAML}
      />,
    );

    const dialog = await openGuide();

    expect(
      within(dialog).getByText(
        "https://api.example.com/api/v1/accounts/saml/<your-email-domain>/acs/",
      ),
    ).toBeInTheDocument();
    expect(within(dialog).getByText("urn:cloudsneeker:sp")).toBeInTheDocument();
  });
});

describe("ProviderSetupGuideButton", () => {
  beforeEach(() => {
    useProviderWizardStore.getState().reset();
  });

  it("shows the guide for the chosen credential method", async () => {
    useProviderWizardStore.getState().setVia("github_app");
    render(<ProviderSetupGuideButton providerType="github" />);

    const dialog = await openGuide();

    expect(within(dialog).getAllByRole("region")).toHaveLength(1);
    expect(
      within(dialog).getByRole("region", { name: /GitHub App/ }),
    ).toBeInTheDocument();
    expect(document.body.textContent ?? "").not.toMatch(/prowler/i);
  });

  it("lists every method before one is chosen", async () => {
    render(<ProviderSetupGuideButton providerType="github" />);

    const dialog = await openGuide();

    expect(within(dialog).getAllByRole("region")).toHaveLength(3);
  });

  it("renders nothing until a provider type is known", () => {
    const { container } = render(<ProviderSetupGuideButton />);

    expect(container).toBeEmptyDOMElement();
  });
});
