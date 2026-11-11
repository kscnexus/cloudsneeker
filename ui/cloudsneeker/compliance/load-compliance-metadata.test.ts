import { beforeEach, describe, expect, it, vi } from "vitest";

const { getComplianceOverviewMetadataInfoMock } = vi.hoisted(() => ({
  getComplianceOverviewMetadataInfoMock: vi.fn(),
}));

vi.mock("@/actions/compliances", () => ({
  getComplianceOverviewMetadataInfo: getComplianceOverviewMetadataInfoMock,
}));

import { loadComplianceMetadata } from "./load-compliance-metadata";

describe("loadComplianceMetadata", () => {
  beforeEach(() => {
    getComplianceOverviewMetadataInfoMock.mockReset();
  });

  it("returns the metadata of the scan", async () => {
    // Given
    const metadata = { data: { attributes: { regions: ["us-east-1"] } } };
    getComplianceOverviewMetadataInfoMock.mockResolvedValue(metadata);
    // When
    const result = await loadComplianceMetadata("scan-1");
    // Then
    expect(result).toEqual(metadata);
    expect(getComplianceOverviewMetadataInfoMock).toHaveBeenCalledWith({
      filters: { "filter[scan_id]": "scan-1" },
    });
  });

  it("returns null when the API reports that the compliance task failed", async () => {
    // Given - handleApiResponse throws on 5xx
    getComplianceOverviewMetadataInfoMock.mockRejectedValue(
      new Error("Task failed to generate compliance overview data."),
    );
    // When
    const result = await loadComplianceMetadata("scan-1");
    // Then
    expect(result).toBeNull();
  });

  it("keeps an empty result when the request itself failed", async () => {
    // Given
    getComplianceOverviewMetadataInfoMock.mockResolvedValue(undefined);
    // When
    const result = await loadComplianceMetadata("scan-1");
    // Then
    expect(result).toEqual({});
  });
});
