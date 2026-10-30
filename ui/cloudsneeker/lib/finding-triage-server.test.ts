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

import { withCloudsneekerTriage } from "./finding-triage-server";

const findings = {
  data: [
    { id: "finding-1", attributes: { uid: "uid-1" } },
    { id: "finding-2", attributes: { uid: "uid-2" } },
  ],
};

describe("withCloudsneekerTriage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
  });

  it("looks up the rows by finding id and merges the result", async () => {
    handleApiResponseMock.mockResolvedValue({
      data: [
        {
          id: "finding-2",
          attributes: {
            finding_id: "finding-2",
            finding_uid: "uid-2",
            triage_id: "triage-2",
            triage_status: "false_positive",
            triage_notes_count: 0,
            triage_has_note: false,
          },
        },
      ],
    });

    const result = await withCloudsneekerTriage(findings);

    const url = new URL(fetchMock.mock.calls[0][0]);
    expect(url.pathname).toBe("/api/v1/finding-triages/lookup");
    expect(url.searchParams.get("filter[finding_id__in]")).toBe(
      "finding-1,finding-2",
    );
    expect(result.data[0]).toBe(findings.data[0]);
    expect(result.data[1].attributes).toMatchObject({
      triage_id: "triage-2",
      triage_status: "false_positive",
    });
  });

  it("skips the request when no row needs triage", async () => {
    const response = { data: [] };

    expect(await withCloudsneekerTriage(response)).toBe(response);
    expect(await withCloudsneekerTriage(undefined)).toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns the findings unchanged when the lookup fails", async () => {
    const consoleError = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});
    fetchMock.mockRejectedValue(new Error("network"));

    expect(await withCloudsneekerTriage(findings)).toBe(findings);
    consoleError.mockRestore();
  });
});
