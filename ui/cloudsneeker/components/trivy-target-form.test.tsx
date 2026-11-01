import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { TrivyTargetForm } from "./trivy-target-form";

const { createMock, pushMock } = vi.hoisted(() => ({
  createMock: vi.fn(),
  pushMock: vi.fn(),
}));

vi.mock("@/cloudsneeker/actions/trivy", () => ({
  createTrivyTarget: createMock,
  updateTrivyTarget: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, refresh: vi.fn() }),
}));

class ResizeObserverMock {
  observe() {}
  unobserve() {}
  disconnect() {}
}

Object.defineProperty(globalThis, "ResizeObserver", {
  writable: true,
  configurable: true,
  value: ResizeObserverMock,
});

Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
  writable: true,
  configurable: true,
  value: vi.fn(),
});

const providers = [
  {
    id: "11111111-1111-4111-8111-111111111111",
    label: "Code repository · acme/app",
    providerType: "iac",
  },
  {
    id: "22222222-2222-4222-8222-222222222222",
    label: "Kubernetes · prod",
    providerType: "kubernetes",
  },
];

const scanTypes = () => screen.getByRole("combobox", { name: "Scan types" });

describe("TrivyTargetForm", () => {
  beforeEach(() => {
    createMock.mockReset();
    pushMock.mockReset();
  });

  it("starts as a code repository scan with every repository scan type", () => {
    render(<TrivyTargetForm providers={providers} />);

    expect(screen.getByLabelText("Mode")).toHaveValue("repo");
    for (const label of [
      "Vulnerabilities",
      "Misconfigurations (IaC)",
      "Secrets",
      "Licenses",
    ]) {
      expect(within(scanTypes()).getByText(label)).toBeInTheDocument();
    }
    expect(
      screen.getByText(/Requires a Code repository source/),
    ).toBeInTheDocument();
  });

  it("lists only the scan types the selected mode supports", async () => {
    const user = userEvent.setup();
    render(<TrivyTargetForm providers={providers} />);

    await user.selectOptions(screen.getByLabelText("Mode"), "k8s");
    await user.click(scanTypes());

    const options = screen
      .getAllByRole("option")
      .map((item) => item.textContent ?? "");
    expect(options.some((text) => text.startsWith("RBAC"))).toBe(true);
    expect(options.some((text) => text.startsWith("Licenses"))).toBe(false);
  });

  it("sends the chosen scan types to the API", async () => {
    const user = userEvent.setup();
    createMock.mockResolvedValue({ data: { id: "t-1" } });
    render(<TrivyTargetForm providers={providers} />);

    await user.type(screen.getByLabelText("Name"), "App repo");
    await user.type(
      screen.getByLabelText("Repository URL"),
      "https://github.com/acme/app",
    );
    await user.click(scanTypes());
    await user.click(screen.getByRole("option", { name: /^Licenses/ }));
    await user.click(screen.getByRole("button", { name: "Create target" }));

    expect(createMock).toHaveBeenCalledWith(
      expect.objectContaining({
        mode: "repo",
        config: {
          scanners: ["vuln", "misconfig", "secret"],
          repository_url: "https://github.com/acme/app",
        },
      }),
    );
  });
});
