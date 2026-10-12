import { beforeEach, describe, expect, it, vi } from "vitest";

const { fetchMock, getAuthHeadersMock, handleApiResponseMock } = vi.hoisted(
  () => ({
    fetchMock: vi.fn(),
    getAuthHeadersMock: vi.fn(),
    handleApiResponseMock: vi.fn(),
  }),
);

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiResponse: handleApiResponseMock,
}));

import { getBrand } from "./brand";

const brandResponse = {
  data: {
    type: "cloudsneeker-brand",
    id: "cloudsneeker",
    attributes: {
      name: "Cloudsneeker",
      short_name: "Cloudsneeker",
      vendor: "Cloudsneeker",
      tagline: "Cloud security posture, continuously.",
      website_url: "https://cloudsneeker.example",
      docs_url: "https://docs.cloudsneeker.example",
      support_url: "https://support.cloudsneeker.example",
      status_url: "",
      terms_url: "https://cloudsneeker.example/terms",
      privacy_url: "https://cloudsneeker.example/privacy",
      logo_url: "",
    },
  },
};

describe("getBrand", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
  });

  it("requests the brand resource with the session headers", async () => {
    // Given
    fetchMock.mockResolvedValue(new Response(null, { status: 200 }));
    handleApiResponseMock.mockResolvedValue(brandResponse);

    // When
    const result = await getBrand();

    // Then
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/api/v1/cloudsneeker/brand",
      expect.objectContaining({
        method: "GET",
        headers: { Authorization: "Bearer token" },
      }),
    );
    expect(result).toEqual(brandResponse);
  });

  it("returns undefined when the request fails", async () => {
    // Given
    fetchMock.mockResolvedValue(
      new Response(null, { status: 401, statusText: "Unauthorized" }),
    );

    // When
    const result = await getBrand();

    // Then
    expect(result).toBeUndefined();
    expect(handleApiResponseMock).not.toHaveBeenCalled();
  });

  it("returns undefined when the network call throws", async () => {
    // Given
    fetchMock.mockRejectedValue(new Error("offline"));

    // When
    const result = await getBrand();

    // Then
    expect(result).toBeUndefined();
  });
});
