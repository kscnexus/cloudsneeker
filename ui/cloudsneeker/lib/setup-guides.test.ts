import { describe, expect, it } from "vitest";

import { PROVIDER_TYPES } from "@/types/providers";

import {
  getIntegrationSetupGuides,
  getProviderSetupGuides,
  resolveSetupGuideText,
  SETUP_GUIDE_INTEGRATION,
  type SetupGuide,
} from "./setup-guides";

const textOf = (guides: readonly SetupGuide[]) => JSON.stringify(guides);

describe("getProviderSetupGuides", () => {
  it.each(PROVIDER_TYPES)("has a guide with steps for %s", (providerType) => {
    const guides = getProviderSetupGuides(providerType);

    expect(guides.length).toBeGreaterThan(0);
    for (const guide of guides) {
      expect(guide.steps.length).toBeGreaterThan(0);
      expect(guide.security.length).toBeGreaterThan(0);
    }
  });

  it("returns only the chosen GitHub method", () => {
    const guides = getProviderSetupGuides("github", "personal_access_token");

    expect(guides).toHaveLength(1);
    expect(guides[0].title).toContain("personal access token");
  });

  it("returns every method before one is chosen", () => {
    const titles = getProviderSetupGuides("github", null).map(
      (guide) => guide.title,
    );

    expect(titles).toHaveLength(3);
    expect(titles.join(" ")).toMatch(/OAuth App/);
    expect(titles.join(" ")).toMatch(/GitHub App/);
  });

  it("ignores a method left over from another provider", () => {
    expect(getProviderSetupGuides("azure", "role")).toHaveLength(1);
  });

  it("falls back to a read-only guide for an unknown provider", () => {
    const [guide] = getProviderSetupGuides("some-new-cloud");

    expect(guide.title).toContain("read-only credential");
  });

  it("returns nothing without a provider type", () => {
    expect(getProviderSetupGuides(null)).toEqual([]);
  });
});

describe("getIntegrationSetupGuides", () => {
  it.each(Object.values(SETUP_GUIDE_INTEGRATION))(
    "has a guide for %s",
    (integration) => {
      const [guide] = getIntegrationSetupGuides(integration);

      expect(guide.steps.length).toBeGreaterThan(0);
      expect(guide.security.length).toBeGreaterThan(0);
    },
  );

  it("gives the Slack redirect URL on this deployment", () => {
    const [guide] = getIntegrationSetupGuides(SETUP_GUIDE_INTEGRATION.SLACK);
    const redirect = guide.values?.find(
      (item) => item.label === "Redirect URL",
    );

    expect(
      resolveSetupGuideText(redirect?.value ?? "", {
        appUrl: "https://app.example.com/",
        apiUrl: "",
      }),
    ).toBe("https://app.example.com/integrations/slack/callback");
  });

  it("gives the SAML ACS URL on the API host", () => {
    const [guide] = getIntegrationSetupGuides(SETUP_GUIDE_INTEGRATION.SAML);
    const acs = guide.values?.find((item) => item.label.startsWith("ACS URL"));

    expect(
      resolveSetupGuideText(acs?.value ?? "", {
        appUrl: "https://app.example.com",
        apiUrl: "https://api.example.com/api/v1",
      }),
    ).toBe(
      "https://api.example.com/api/v1/accounts/saml/<your-email-domain>/acs/",
    );
  });
});

describe("guide copy", () => {
  it("names only the product", () => {
    const everything =
      PROVIDER_TYPES.map((type) =>
        textOf(getProviderSetupGuides(type)),
      ).join() +
      Object.values(SETUP_GUIDE_INTEGRATION)
        .map((integration) => textOf(getIntegrationSetupGuides(integration)))
        .join();

    expect(everything).not.toMatch(/prowler/i);
  });
});
