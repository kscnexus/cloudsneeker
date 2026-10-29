import { describe, expect, it } from "vitest";

import {
  CLOUDSNEEKER_FEATURES,
  isCloudsneekerFeatureEnabled,
} from "./features";

describe("CLOUDSNEEKER_FEATURES", () => {
  it("enables email delivery and slack for integrations", () => {
    expect(CLOUDSNEEKER_FEATURES.emailDelivery).toBe(true);
    expect(CLOUDSNEEKER_FEATURES.slack).toBe(true);
    expect(isCloudsneekerFeatureEnabled("emailDelivery")).toBe(true);
    expect(isCloudsneekerFeatureEnabled("slack")).toBe(true);
  });

  it("enables scan comparison for the Multiple Scans compliance tab", () => {
    expect(CLOUDSNEEKER_FEATURES.scanComparison).toBe(true);
    expect(isCloudsneekerFeatureEnabled("scanComparison")).toBe(true);
  });

  it("enables grouped Jira dispatch", () => {
    expect(CLOUDSNEEKER_FEATURES.jiraGroupedDispatch).toBe(true);
    expect(isCloudsneekerFeatureEnabled("jiraGroupedDispatch")).toBe(true);
  });

  it("enables advanced scan scheduling", () => {
    expect(CLOUDSNEEKER_FEATURES.advancedScheduling).toBe(true);
    expect(isCloudsneekerFeatureEnabled("advancedScheduling")).toBe(true);
  });

  it("enables the reporting area", () => {
    expect(CLOUDSNEEKER_FEATURES.reports).toBe(true);
    expect(isCloudsneekerFeatureEnabled("reports")).toBe(true);
  });
});
