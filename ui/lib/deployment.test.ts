import { afterEach, describe, expect, it, vi } from "vitest";

const importFresh = async () => {
  vi.resetModules();
  return import("./deployment");
};

describe("enterprise feature flags", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("enables grouped Jira dispatch outside cloud via Cloudsneeker", async () => {
    // Given — OSS cloud flag off; Cloudsneeker feature still on.
    vi.stubEnv("UI_CLOUD_ENABLED", "false");

    // When
    const { isGroupedJiraDispatchEnabled } = await importFresh();

    // Then
    expect(isGroupedJiraDispatchEnabled()).toBe(true);
  });

  it("should enable grouped Jira dispatch in cloud without an enterprise flag", async () => {
    // Given
    vi.stubEnv("UI_CLOUD_ENABLED", "true");

    // When
    const { isGroupedJiraDispatchEnabled } = await importFresh();

    // Then
    expect(isGroupedJiraDispatchEnabled()).toBe(true);
  });
});
