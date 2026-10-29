import { describe, expect, it } from "vitest";

import { summarizeAlerts, summarizeScanProfiles } from "./ops-summary";

describe("summarizeAlerts", () => {
  it("counts active, paused and distinct destinations", () => {
    // Given
    const alerts = [
      {
        attributes: {
          enabled: true,
          recipient_emails: ["SecOps@example.com", "ciso@example.com"],
          slack_channels: [{ id: "C1" }],
        },
      },
      {
        attributes: {
          enabled: false,
          recipient_emails: ["secops@example.com "],
          slack_channels: [{ id: "C1" }, { id: "C2" }],
        },
      },
      { attributes: { enabled: true } },
    ];

    // When
    const summary = summarizeAlerts(alerts, 7);

    // Then
    expect(summary).toEqual({
      total: 7,
      loaded: 3,
      active: 2,
      paused: 1,
      destinations: 4,
    });
  });

  it("falls back to the loaded rows when the API count is missing", () => {
    expect(summarizeAlerts([], undefined)).toEqual({
      total: 0,
      loaded: 0,
      active: 0,
      paused: 0,
      destinations: 0,
    });
    expect(summarizeAlerts([{ attributes: { enabled: false } }], 0).total).toBe(
      1,
    );
  });
});

describe("summarizeScanProfiles", () => {
  it("counts covered providers and the newest edit", () => {
    // Given
    const profiles = [
      {
        attributes: {
          providers: ["p1", "p2", "gone"],
          updated_at: "2026-10-01T10:00:00Z",
        },
      },
      {
        attributes: {
          providers: ["p2"],
          updated_at: "2026-10-20T08:30:00Z",
        },
      },
    ];

    // When
    const summary = summarizeScanProfiles(profiles, ["p1", "p2", "p3", "p4"]);

    // Then
    expect(summary).toEqual({
      profiles: 2,
      coveredProviders: 2,
      defaultProviders: 2,
      lastUpdated: "2026-10-20T08:30:00Z",
    });
  });

  it("reports no edit date without profiles", () => {
    expect(summarizeScanProfiles([], ["p1"])).toEqual({
      profiles: 0,
      coveredProviders: 0,
      defaultProviders: 1,
      lastUpdated: null,
    });
  });
});
