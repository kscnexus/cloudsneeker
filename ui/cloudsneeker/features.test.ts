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
});
