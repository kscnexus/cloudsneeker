import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { SeekerAiSetupNeeded } from "./seeker-ai-setup-needed";

vi.mock("@/components/shadcn/content-layout", () => ({
  ContentLayout: ({ children }: { children: React.ReactNode }) => (
    <main>{children}</main>
  ),
}));

describe("SeekerAiSetupNeeded", () => {
  it("explains the assistant and links to the model settings", () => {
    render(<SeekerAiSetupNeeded />);

    expect(
      screen.getByRole("heading", { name: "Connect a model to use Seeker AI" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Connect a model" }),
    ).toHaveAttribute("href", "/lighthouse/settings");
  });
});
