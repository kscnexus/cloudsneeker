import { afterEach, describe, expect, it, vi } from "vitest";

describe("siteConfig", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it("names the application Cloudsneeker", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

    // When
    const { siteConfig } = await import("./site");

    // Then
    expect(siteConfig.name).toBe("Cloudsneeker");
  });

  it("keeps the Cloudsneeker name when cloud mode is enabled", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");

    // When
    const { siteConfig } = await import("./site");

    // Then
    expect(siteConfig.name).toBe("Cloudsneeker");
  });
});
