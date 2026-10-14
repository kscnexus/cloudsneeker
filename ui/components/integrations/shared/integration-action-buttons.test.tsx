import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import type { IntegrationProps } from "@/types/integrations";

import { IntegrationActionButtons } from "./integration-action-buttons";

const permissions = vi.hoisted(() => ({
  manage_account: true,
}));

vi.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ permissions }),
}));

const integration = {
  id: "int-1",
  attributes: { enabled: true },
} as IntegrationProps;

const handlers = {
  onTestConnection: vi.fn(),
  onEditCredentials: vi.fn(),
  onToggleEnabled: vi.fn(),
  onDelete: vi.fn(),
};

describe("IntegrationActionButtons", () => {
  it("shows Delete when the user has manage_account", () => {
    permissions.manage_account = true;

    render(
      <IntegrationActionButtons integration={integration} {...handlers} />,
    );

    expect(screen.getByRole("button", { name: /Delete/i })).toBeInTheDocument();
  });

  it("hides Delete when the user lacks manage_account", () => {
    permissions.manage_account = false;

    render(
      <IntegrationActionButtons integration={integration} {...handlers} />,
    );

    expect(
      screen.queryByRole("button", { name: /Delete/i }),
    ).not.toBeInTheDocument();
  });
});
