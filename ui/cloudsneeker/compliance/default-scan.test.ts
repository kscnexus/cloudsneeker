import { describe, expect, it } from "vitest";

import type { ExpandedScanData } from "@/types";

import { defaultComplianceScanId } from "./default-scan";

const scan = (id: string, provider: string) =>
  ({
    id,
    providerInfo: { provider, uid: id, alias: id },
  }) as unknown as ExpandedScanData;

describe("defaultComplianceScanId", () => {
  it("skips newer IaC and image scans for the newest cloud scan", () => {
    expect(
      defaultComplianceScanId([
        scan("iac-1", "iac"),
        scan("image-1", "image"),
        scan("aws-1", "aws"),
        scan("gcp-1", "gcp"),
      ]),
    ).toBe("aws-1");
  });

  it("keeps the newest scan when it has compliance", () => {
    expect(
      defaultComplianceScanId([scan("azure-1", "azure"), scan("iac-1", "iac")]),
    ).toBe("azure-1");
  });

  it("falls back to the newest scan when none has compliance", () => {
    expect(
      defaultComplianceScanId([scan("iac-1", "iac"), scan("image-1", "image")]),
    ).toBe("iac-1");
  });

  it("returns undefined without scans", () => {
    expect(defaultComplianceScanId([])).toBeUndefined();
  });
});
