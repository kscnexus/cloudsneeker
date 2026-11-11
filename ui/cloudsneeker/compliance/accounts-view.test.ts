import { describe, expect, it } from "vitest";

import {
  MULTI_SCAN_VIEW,
  multiScanViewHref,
  multiScanViewOf,
  providerTypeOptions,
  selectedProviderType,
} from "./accounts-view";

const scan = (provider: string, account: string) => ({
  providerInfo: { provider, uid: account },
  relationships: { provider: { data: { id: account } } },
});

describe("accounts view", () => {
  it("reads the view from the URL", () => {
    expect(multiScanViewOf({ view: "accounts" })).toBe(
      MULTI_SCAN_VIEW.ACCOUNTS,
    );
    expect(multiScanViewOf({})).toBe(MULTI_SCAN_VIEW.SCANS);
    expect(multiScanViewOf({ view: "other" })).toBe(MULTI_SCAN_VIEW.SCANS);
  });

  it("lists cloud then SaaS provider types with account counts", () => {
    const options = providerTypeOptions([
      scan("m365", "t1"),
      scan("aws", "a1"),
      scan("aws", "a1"),
      scan("aws", "a2"),
      scan("iac", "repo"),
    ]);
    expect(options.map((option) => [option.value, option.accounts])).toEqual([
      ["aws", 2],
      ["m365", 1],
    ]);
  });

  it("keeps a valid provider type and falls back to the first", () => {
    const options = providerTypeOptions([scan("aws", "a"), scan("gcp", "g")]);
    expect(selectedProviderType({ providerType: "gcp" }, options)).toBe("gcp");
    expect(selectedProviderType({ providerType: "iac" }, options)).toBe("aws");
    expect(selectedProviderType({}, [])).toBeNull();
  });

  it("links to each view", () => {
    expect(multiScanViewHref(MULTI_SCAN_VIEW.ACCOUNTS, "aws")).toBe(
      "/compliance?tab=cross-provider&view=accounts&providerType=aws",
    );
    expect(multiScanViewHref(MULTI_SCAN_VIEW.SCANS, "aws")).toBe(
      "/compliance?tab=cross-provider",
    );
  });
});
