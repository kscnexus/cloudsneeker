import { describe, expect, it } from "vitest";

import {
  CUSTODIAN_PROVIDER_TYPES,
  isCustodianProviderType,
} from "./custodian-providers";

describe("custodian providers", () => {
  it("lists every Cloud Custodian cloud Cloudsneeker can attach", () => {
    expect(CUSTODIAN_PROVIDER_TYPES).toEqual([
      "aws",
      "azure",
      "gcp",
      "kubernetes",
    ]);
  });

  it("accepts supported types and rejects others", () => {
    expect(isCustodianProviderType("azure")).toBe(true);
    expect(isCustodianProviderType("github")).toBe(false);
  });
});
