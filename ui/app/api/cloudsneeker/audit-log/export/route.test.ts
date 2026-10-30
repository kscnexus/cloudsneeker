import { beforeEach, describe, expect, it, vi } from "vitest";

const getAuthHeadersMock = vi.fn();
const fetchMock = vi.fn();

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example",
  getAuthHeaders: (...args: unknown[]) => getAuthHeadersMock(...args),
}));

const callRoute = async (query = "") => {
  const { GET } = await import("./route");
  return GET(
    new Request(`https://ui.example/api/cloudsneeker/audit-log/export${query}`),
  );
};

describe("audit log export route", () => {
  beforeEach(() => {
    vi.resetModules();
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer x" });
  });

  it("streams the CSV with only allow-listed filters", async () => {
    fetchMock.mockResolvedValue(
      new Response("time,actor_email\n", {
        status: 200,
        headers: {
          "content-type": "text/csv; charset=utf-8",
          "content-disposition":
            'attachment; filename="audit-log-2026-10-30.csv"',
        },
      }),
    );

    const response = await callRoute(
      "?format=csv&filter%5Boutcome%5D=failure&evil=1",
    );

    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example/audit-events/export?format=csv&filter%5Boutcome%5D=failure",
      expect.objectContaining({ headers: { Authorization: "Bearer x" } }),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/csv");
    expect(response.headers.get("content-disposition")).toContain(
      "audit-log-2026-10-30.csv",
    );
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.text()).toBe("time,actor_email\n");
  });

  it("defaults to CSV and rejects other formats without calling the API", async () => {
    fetchMock.mockResolvedValue(new Response("x", { status: 200 }));
    await callRoute();
    expect(fetchMock.mock.calls[0][0]).toContain("format=csv");

    fetchMock.mockClear();
    expect((await callRoute("?format=xlsx")).status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("passes API errors through", async () => {
    fetchMock.mockResolvedValue(
      new Response('{"errors":[{"detail":"Forbidden"}]}', {
        status: 403,
        headers: { "content-type": "application/vnd.api+json" },
      }),
    );

    const response = await callRoute("?format=csv");

    expect(response.status).toBe(403);
    expect(await response.text()).toContain("Forbidden");
  });

  it("returns 502 when the API is unreachable", async () => {
    fetchMock.mockRejectedValue(new Error("down"));
    expect((await callRoute("?format=csv")).status).toBe(502);
  });
});
