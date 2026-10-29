import { beforeEach, describe, expect, it, vi } from "vitest";

import LegacyGovernancePage from "./page";

const { permanentRedirectMock } = vi.hoisted(() => ({
  permanentRedirectMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  permanentRedirect: permanentRedirectMock,
}));

describe("legacy /custodian routes", () => {
  beforeEach(() => {
    permanentRedirectMock.mockReset();
  });

  it("redirects the hub to Cloud Governance with its tab", async () => {
    await LegacyGovernancePage({
      params: Promise.resolve({}),
      searchParams: Promise.resolve({ tab: "reports" }),
    });

    expect(permanentRedirectMock).toHaveBeenCalledWith(
      "/governance?tab=reports",
    );
  });

  it("keeps the policy id and sub-path", async () => {
    await LegacyGovernancePage({
      params: Promise.resolve({ path: ["p-1", "edit"] }),
      searchParams: Promise.resolve({}),
    });

    expect(permanentRedirectMock).toHaveBeenCalledWith("/governance/p-1/edit");
  });
});
