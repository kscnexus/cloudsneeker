import { beforeEach, describe, expect, it, vi } from "vitest";

import LegacyAppSecurityPage from "./page";

const { permanentRedirectMock } = vi.hoisted(() => ({
  permanentRedirectMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  permanentRedirect: permanentRedirectMock,
}));

describe("legacy /trivy routes", () => {
  beforeEach(() => {
    permanentRedirectMock.mockReset();
  });

  it("redirects the hub to Application Security", async () => {
    await LegacyAppSecurityPage({
      params: Promise.resolve({}),
      searchParams: Promise.resolve({}),
    });

    expect(permanentRedirectMock).toHaveBeenCalledWith("/application-security");
  });

  it("keeps the target and run ids", async () => {
    await LegacyAppSecurityPage({
      params: Promise.resolve({ path: ["t-1", "runs", "r-1"] }),
      searchParams: Promise.resolve({}),
    });

    expect(permanentRedirectMock).toHaveBeenCalledWith(
      "/application-security/t-1/runs/r-1",
    );
  });
});
