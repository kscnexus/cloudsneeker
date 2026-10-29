import { beforeEach, describe, expect, it, vi } from "vitest";

const getAuthHeadersMock = vi.fn();
const fetchMock = vi.fn();

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example",
  getAuthHeaders: (...args: unknown[]) => getAuthHeadersMock(...args),
}));

const RUN_ID = "22222222-2222-4222-8222-222222222222";

const callRoute = async (runId: string, query = "") => {
  const { GET } = await import("./route");
  return GET(
    new Request(
      `https://ui.example/api/cloudsneeker/reports/${runId}/download${query}`,
    ),
    { params: Promise.resolve({ runId }) },
  );
};

describe("report download route", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer x" });
  });

  it("streams the artifact with the API filename and type", async () => {
    fetchMock.mockResolvedValue(
      new Response("xlsx-bytes", {
        status: 200,
        headers: {
          "content-type":
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
          "content-disposition":
            'attachment; filename="cloudsneeker-executive-2026-10-28.xlsx"',
        },
      }),
    );

    const response = await callRoute(RUN_ID, "?format=xlsx");

    expect(fetchMock).toHaveBeenCalledWith(
      `https://api.example/report-runs/${RUN_ID}/download?format=xlsx`,
      expect.objectContaining({ headers: { Authorization: "Bearer x" } }),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-disposition")).toContain(
      "cloudsneeker-executive-2026-10-28.xlsx",
    );
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.text()).toBe("xlsx-bytes");
  });

  it("defaults to PDF and fills in missing headers", async () => {
    fetchMock.mockResolvedValue(new Response("pdf", { status: 200 }));

    const response = await callRoute(RUN_ID);

    expect(fetchMock.mock.calls[0][0]).toContain("format=pdf");
    expect(response.headers.get("content-type")).toContain("text/plain");
  });

  it("rejects bad run ids and formats without calling the API", async () => {
    expect((await callRoute("../users", "?format=pdf")).status).toBe(404);
    expect((await callRoute(RUN_ID, "?format=exe")).status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("passes API errors through", async () => {
    fetchMock.mockResolvedValue(
      new Response('{"errors":[{"detail":"Report run not found."}]}', {
        status: 404,
        headers: { "content-type": "application/vnd.api+json" },
      }),
    );

    const response = await callRoute(RUN_ID, "?format=csv");

    expect(response.status).toBe(404);
    expect(await response.text()).toContain("Report run not found.");
  });
});
