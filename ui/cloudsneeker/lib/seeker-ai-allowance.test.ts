import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  recordSeekerAiRequest,
  SEEKER_AI_DENIAL_FALLBACK,
  seekerAiAllowanceResponse,
} from "./seeker-ai-allowance";

const { getAuthHeadersMock } = vi.hoisted(() => ({
  getAuthHeadersMock: vi.fn(),
}));

vi.mock("@/lib/helper", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

const LIMIT_DETAIL =
  "The Professional plan allows 500 assistant requests per month; this organization has used 500 this month.";

const jsonResponse = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/vnd.api+json" },
  });

describe("recordSeekerAiRequest", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("records the request and lets the chat run", async () => {
    fetchMock.mockResolvedValue(jsonResponse(201, { data: {} }));

    expect(await recordSeekerAiRequest()).toBeNull();
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/api/v1/seeker-ai/requests",
      expect.objectContaining({ method: "POST", cache: "no-store" }),
    );
  });

  it("returns the reason when the monthly allowance is used", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(403, {
        errors: [{ code: "plan_limit_reached", detail: LIMIT_DETAIL }],
      }),
    );

    expect(await recordSeekerAiRequest()).toBe(LIMIT_DETAIL);
  });

  it("falls back to a plain reason when the 403 has no detail", async () => {
    fetchMock.mockResolvedValue(new Response("<html>", { status: 403 }));

    expect(await recordSeekerAiRequest()).toBe(SEEKER_AI_DENIAL_FALLBACK);
  });

  it.each([401, 404, 500])("lets the chat run on a %i", async (status) => {
    fetchMock.mockResolvedValue(jsonResponse(status, { errors: [] }));

    expect(await recordSeekerAiRequest()).toBeNull();
  });

  it("lets the chat run when the API cannot be reached", async () => {
    fetchMock.mockRejectedValue(new Error("network down"));

    expect(await recordSeekerAiRequest()).toBeNull();
  });

  it("answers a refused request with the reason as a chat error", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(403, { errors: [{ detail: LIMIT_DETAIL }] }),
    );

    const response = await seekerAiAllowanceResponse();

    expect(response).not.toBeNull();
    const text = await (response as Response).text();
    expect(text).toContain(LIMIT_DETAIL);
    expect(text).toContain("[LIGHTHOUSE_ANALYST_ERROR]");
  });

  it("returns no response when the chat may run", async () => {
    fetchMock.mockResolvedValue(jsonResponse(201, { data: {} }));

    expect(await seekerAiAllowanceResponse()).toBeNull();
  });
});
