import { beforeEach, describe, expect, it, vi } from "vitest";

const getAuthHeadersMock = vi.fn();
const handleApiResponseMock = vi.fn();
const handleApiErrorMock = vi.fn();
const revalidatePathMock = vi.fn();
const fetchMock = vi.fn();

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example",
  getAuthHeaders: (...args: unknown[]) => getAuthHeadersMock(...args),
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiResponse: (...args: unknown[]) => handleApiResponseMock(...args),
  handleApiError: (...args: unknown[]) => handleApiErrorMock(...args),
}));

vi.mock("next/cache", () => ({
  revalidatePath: (...args: unknown[]) => revalidatePathMock(...args),
}));

const PROVIDER_ID = "11111111-1111-4111-8111-111111111111";

const requestBody = (call = 0) =>
  JSON.parse(fetchMock.mock.calls[call][1].body as string);

describe("report server actions", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer x" });
    fetchMock.mockResolvedValue({ ok: true });
    handleApiResponseMock.mockResolvedValue({ data: { id: "run-1" } });
  });

  it("creates a report run with the JSON:API envelope", async () => {
    const { createReportRun } = await import("./reports");
    await createReportRun({
      reportType: "compliance",
      params: { provider_ids: [PROVIDER_ID], compliance_id: "cis_2.0_aws" },
      formats: ["pdf", "xlsx"],
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example/report-runs",
      expect.objectContaining({ method: "POST" }),
    );
    expect(requestBody()).toEqual({
      data: {
        type: "cloudsneeker-report-runs",
        attributes: {
          report_type: "compliance",
          params: { provider_ids: [PROVIDER_ID], compliance_id: "cis_2.0_aws" },
          formats: ["pdf", "xlsx"],
        },
      },
    });
    expect(revalidatePathMock).toHaveBeenCalledWith("/reports");
  });

  it("creates a share link with the chosen expiry", async () => {
    const { createReportShareLink } = await import("./reports");
    await createReportShareLink("run-1", 168);

    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example/report-runs/run-1/share-links",
      expect.objectContaining({ method: "POST" }),
    );
    expect(requestBody().data.attributes).toEqual({ expires_in_hours: 168 });
  });

  it("revokes a share link", async () => {
    const { revokeReportShareLink } = await import("./reports");
    await revokeReportShareLink("link-1");

    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example/report-share-links/link-1/revoke",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("patches a schedule with every field", async () => {
    const { updateReportSchedule } = await import("./reports");
    await updateReportSchedule("schedule-1", {
      name: "Weekly exec",
      reportType: "executive",
      params: { provider_ids: [] },
      formats: ["pdf"],
      scheduleCron: "0 8 * * 1",
      scheduleTimezone: "Asia/Kolkata",
      recipients: ["ciso@example.com"],
      enabled: true,
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example/report-schedules/schedule-1",
      expect.objectContaining({ method: "PATCH" }),
    );
    expect(requestBody().data).toEqual({
      type: "cloudsneeker-report-schedules",
      id: "schedule-1",
      attributes: {
        name: "Weekly exec",
        report_type: "executive",
        params: { provider_ids: [] },
        formats: ["pdf"],
        schedule_cron: "0 8 * * 1",
        schedule_timezone: "Asia/Kolkata",
        recipients: ["ciso@example.com"],
        enabled: true,
      },
    });
  });

  it("toggles a schedule with only the enabled flag", async () => {
    const { setReportScheduleEnabled } = await import("./reports");
    await setReportScheduleEnabled("schedule-1", false);

    expect(requestBody().data.attributes).toEqual({ enabled: false });
  });

  it("deletes a run without a body", async () => {
    const { deleteReportRun } = await import("./reports");
    await deleteReportRun("run-1");

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://api.example/report-runs/run-1");
    expect(init.method).toBe("DELETE");
    expect(init.body).toBeUndefined();
    expect(getAuthHeadersMock).toHaveBeenCalledWith({ contentType: false });
  });

  it("lists runs with query parameters", async () => {
    const { listReportRuns } = await import("./reports");
    await listReportRuns({ "page[size]": "50", sort: "-inserted_at", x: "" });

    expect(fetchMock.mock.calls[0][0]).toBe(
      "https://api.example/report-runs?page%5Bsize%5D=50&sort=-inserted_at",
    );
  });

  it("returns handleApiError when fetch throws", async () => {
    fetchMock.mockRejectedValue(new Error("network down"));
    handleApiErrorMock.mockReturnValue({ error: "network down" });

    const { getReportRunData } = await import("./reports");
    const result = await getReportRunData("run-1");

    expect(result).toEqual({ error: "network down" });
  });
});
