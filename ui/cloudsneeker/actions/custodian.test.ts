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

describe("dryRunCustodianPolicy", () => {
  beforeEach(() => {
    vi.resetModules();
    getAuthHeadersMock.mockReset();
    handleApiResponseMock.mockReset();
    handleApiErrorMock.mockReset();
    revalidatePathMock.mockReset();
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  it("posts to the dry-run endpoint and revalidates the policy page", async () => {
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer x" });
    fetchMock.mockResolvedValue({ ok: true });
    handleApiResponseMock.mockResolvedValue({
      data: { id: "run-1", attributes: { status: "pending" } },
    });

    const { dryRunCustodianPolicy } = await import("./custodian");
    const result = await dryRunCustodianPolicy("policy-1");

    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("/custodian-policies/policy-1/dry-run"),
      expect.objectContaining({ method: "POST" }),
    );
    expect(revalidatePathMock).toHaveBeenCalledWith("/custodian/policy-1");
    expect(result).toMatchObject({
      data: { id: "run-1" },
    });
  });

  it("returns handleApiError when fetch throws", async () => {
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer x" });
    fetchMock.mockRejectedValue(new Error("network down"));
    handleApiErrorMock.mockReturnValue({ error: "network down" });

    const { dryRunCustodianPolicy } = await import("./custodian");
    const result = await dryRunCustodianPolicy("policy-1");

    expect(handleApiErrorMock).toHaveBeenCalled();
    expect(result).toEqual({ error: "network down" });
  });
});
