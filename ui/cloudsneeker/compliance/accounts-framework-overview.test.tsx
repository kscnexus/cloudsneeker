import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { loadMock } = vi.hoisted(() => ({ loadMock: vi.fn() }));

vi.mock("@/cloudsneeker/lib/dashboard-data", () => ({
  loadComplianceFrameworks: loadMock,
}));

import { AccountsFrameworkOverview } from "./accounts-framework-overview";

const options = [
  { value: "aws", label: "AWS", accounts: 2 },
  { value: "azure", label: "Azure", accounts: 1 },
];

describe("AccountsFrameworkOverview", () => {
  beforeEach(() => loadMock.mockReset());

  it("loads frameworks for the provider type, most failed first", async () => {
    // Given
    loadMock.mockResolvedValue([
      {
        id: "cis",
        label: "CIS 3.0",
        passed: 50,
        failed: 10,
        manual: 0,
        total: 60,
        score: 83,
      },
      {
        id: "pci",
        label: "PCI 4.0",
        passed: 10,
        failed: 40,
        manual: 5,
        total: 55,
        score: 18,
      },
    ]);

    // When
    render(await AccountsFrameworkOverview({ options, providerType: "aws" }));

    // Then
    expect(loadMock).toHaveBeenCalledWith({ "filter[provider_type]": "aws" });
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows[0]).toHaveTextContent("PCI 4.0");
    expect(rows[1]).toHaveTextContent("CIS 3.0");
    expect(
      screen.getByText("AWS frameworks across accounts"),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Azure · 1" })).toHaveAttribute(
      "href",
      "/compliance?tab=cross-provider&view=accounts&providerType=azure",
    );
  });

  it("explains a load failure", async () => {
    loadMock.mockResolvedValue(null);
    render(await AccountsFrameworkOverview({ options, providerType: "aws" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Compliance results could not be loaded",
    );
  });

  it("explains when no provider has scans", async () => {
    render(
      await AccountsFrameworkOverview({ options: [], providerType: null }),
    );
    expect(screen.getByText("No cloud or SaaS scans yet")).toBeInTheDocument();
    expect(loadMock).not.toHaveBeenCalled();
  });
});
