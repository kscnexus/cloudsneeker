import { describe, expect, it, vi } from "vitest";

import {
  COMPLIANCE_DEFAULT_CANDIDATES,
  selectComplianceScan,
} from "./scan-availability";

const scan = (id: string, provider = "aws") =>
  ({ id, providerInfo: { provider } }) as never;

const metadata = (regions: string[]) => ({
  data: { attributes: { regions } },
});

describe("selectComplianceScan", () => {
  it("keeps the scan named in the URL and returns its metadata", async () => {
    // Given
    const load = vi.fn().mockResolvedValue(metadata(["eu-west-1"]));
    // When
    const result = await selectComplianceScan("s-2", [scan("s-1")], load);
    // Then
    expect(result).toEqual({
      scanId: "s-2",
      metadata: metadata(["eu-west-1"]),
      unavailable: false,
    });
    expect(load).toHaveBeenCalledWith("s-2");
  });

  it("marks the URL scan unavailable when its compliance data failed", async () => {
    // Given
    const load = vi.fn().mockResolvedValue(null);
    // When
    const result = await selectComplianceScan("s-2", [scan("s-1")], load);
    // Then
    expect(result).toEqual({
      scanId: "s-2",
      metadata: null,
      unavailable: true,
    });
  });

  it("skips a default scan whose compliance data failed", async () => {
    // Given
    const load = vi
      .fn()
      .mockImplementation(async (id: string) =>
        id === "broken" ? null : metadata(["us-east-1"]),
      );
    // When
    const result = await selectComplianceScan(
      undefined,
      [scan("broken"), scan("good")],
      load,
    );
    // Then
    expect(result.scanId).toBe("good");
    expect(result.unavailable).toBe(false);
  });

  it("prefers scans with compliance frameworks over code and image scans", async () => {
    // Given
    const load = vi.fn().mockResolvedValue(metadata([]));
    // When
    const result = await selectComplianceScan(
      undefined,
      [scan("code", "iac"), scan("cloud")],
      load,
    );
    // Then
    expect(result.scanId).toBe("cloud");
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("stops after a bounded number of failed candidates", async () => {
    // Given
    const load = vi.fn().mockResolvedValue(null);
    const scans = Array.from({ length: 10 }, (_, index) => scan(`s-${index}`));
    // When
    const result = await selectComplianceScan(undefined, scans, load);
    // Then
    expect(load).toHaveBeenCalledTimes(COMPLIANCE_DEFAULT_CANDIDATES);
    expect(result).toEqual({
      scanId: "s-0",
      metadata: null,
      unavailable: true,
    });
  });

  it("returns no scan when there are none", async () => {
    // Given
    const load = vi.fn();
    // When
    const result = await selectComplianceScan(undefined, [], load);
    // Then
    expect(result).toEqual({
      scanId: null,
      metadata: null,
      unavailable: false,
    });
    expect(load).not.toHaveBeenCalled();
  });
});
