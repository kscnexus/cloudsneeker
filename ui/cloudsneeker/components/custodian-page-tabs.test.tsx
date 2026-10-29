import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { CUSTODIAN_TAB } from "@/cloudsneeker/lib/custodian-dashboard";

import { CustodianPageTabs } from "./custodian-page-tabs";

const { pushMock } = vi.hoisted(() => ({
  pushMock: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
}));

describe("CustodianPageTabs", () => {
  beforeEach(() => {
    pushMock.mockClear();
  });

  it("renders Dashboard, Policies, and Reports tabs", () => {
    render(
      <CustodianPageTabs
        activeTab={CUSTODIAN_TAB.DASHBOARD}
        dashboardContent={<div>Dashboard body</div>}
        policiesContent={<div>Policies body</div>}
        reportsContent={<div>Reports body</div>}
      />,
    );

    expect(
      screen.getAllByRole("tab").map((tab) => tab.textContent),
    ).toStrictEqual(["Dashboard", "Policies", "Reports"]);
    expect(screen.getByText("Dashboard body")).toBeInTheDocument();
  });

  it("navigates to reports and policies via query tabs", async () => {
    const user = userEvent.setup();
    render(
      <CustodianPageTabs
        activeTab={CUSTODIAN_TAB.DASHBOARD}
        dashboardContent={<div>Dashboard body</div>}
        policiesContent={<div>Policies body</div>}
        reportsContent={<div>Reports body</div>}
      />,
    );

    await user.click(screen.getByRole("tab", { name: /reports/i }));
    expect(pushMock).toHaveBeenCalledWith("/governance?tab=reports");

    await user.click(screen.getByRole("tab", { name: /policies/i }));
    expect(pushMock).toHaveBeenCalledWith("/governance?tab=policies");
  });
});
