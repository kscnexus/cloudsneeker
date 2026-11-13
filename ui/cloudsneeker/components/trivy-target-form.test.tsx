import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { TrivyTargetForm } from "./trivy-target-form";

const { createMock, pushMock, branchesMock } = vi.hoisted(() => ({
  createMock: vi.fn(),
  pushMock: vi.fn(),
  branchesMock: vi.fn(),
}));

vi.mock("@/cloudsneeker/actions/appsec", () => ({
  listRepositoryBranches: branchesMock,
}));

vi.mock("@/cloudsneeker/actions/trivy", () => ({
  createTrivyTarget: createMock,
  updateTrivyTarget: vi.fn(),
}));

vi.mock("@/cloudsneeker/actions/sbom", () => ({
  generateSbomFromDescription: vi.fn(),
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
    id: "33333333-3333-4333-8333-333333333333",
    label: "aws · 123456789012",
    providerType: "aws",
  },
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
    branchesMock.mockReset();
    branchesMock.mockResolvedValue({
      data: [
        { id: "main", type: "b", attributes: { name: "main", default: true } },
        {
          id: "develop",
          type: "b",
          attributes: { name: "develop", default: false },
        },
      ],
      meta: { default_branch: "main", truncated: false },
    });
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

  it("picks a provider the selected mode can use", async () => {
    const user = userEvent.setup();
    render(<TrivyTargetForm providers={providers} />);

    expect(screen.getByLabelText("Provider")).toHaveValue(
      "11111111-1111-4111-8111-111111111111",
    );
    await user.selectOptions(screen.getByLabelText("Mode"), "k8s");
    expect(screen.getByLabelText("Provider")).toHaveValue(
      "22222222-2222-4222-8222-222222222222",
    );
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

  it("lists the source's branches with the default first", async () => {
    const user = userEvent.setup();
    render(<TrivyTargetForm providers={providers} />);

    const branches = await screen.findByRole("combobox", { name: "Branches" });
    expect(branchesMock).toHaveBeenCalledWith(
      "11111111-1111-4111-8111-111111111111",
    );
    expect(
      within(branches).getByText("Default branch (main)"),
    ).toBeInTheDocument();
    await user.click(branches);
    const names = within(screen.getByRole("listbox"))
      .getAllByRole("option")
      .map((item) => item.textContent ?? "");
    expect(names[0]).toMatch(/^main/);
    expect(names).toContain("develop");
  });

  it("creates one target per selected branch", async () => {
    const user = userEvent.setup();
    createMock
      .mockResolvedValueOnce({ data: { id: "t-1" } })
      .mockResolvedValueOnce({ data: { id: "t-2" } });
    render(<TrivyTargetForm providers={providers} />);

    await user.type(screen.getByLabelText("Name"), "App repo");
    await user.type(
      screen.getByLabelText("Repository URL"),
      "git@bitbucket.org:acme/app.git",
    );
    await user.click(await screen.findByRole("combobox", { name: "Branches" }));
    await user.click(screen.getByRole("option", { name: /^main/ }));
    await user.click(screen.getByRole("option", { name: "develop" }));
    await user.keyboard("{Escape}");
    await user.click(screen.getByRole("button", { name: "Create target" }));

    expect(createMock).toHaveBeenCalledTimes(2);
    expect(createMock.mock.calls.map(([payload]) => payload.name)).toEqual([
      "App repo @ main",
      "App repo @ develop",
    ]);
    expect(createMock.mock.calls[1][0].config).toMatchObject({
      repository_url: "git@bitbucket.org:acme/app.git",
      branch: "develop",
    });
    expect(pushMock).toHaveBeenCalledWith("/application-security");
  });

  it("lets the branch be typed when the listing fails", async () => {
    const user = userEvent.setup();
    branchesMock.mockResolvedValue({
      error: "The Git server refused the key.",
    });
    createMock.mockResolvedValue({ data: { id: "t-1" } });
    render(<TrivyTargetForm providers={providers} />);

    await user.type(screen.getByLabelText("Name"), "App repo");
    await user.type(
      screen.getByLabelText("Repository URL"),
      "git@bitbucket.org:acme/app.git",
    );
    expect(
      await screen.findByText(/The Git server refused the key\./),
    ).toBeInTheDocument();
    await user.type(screen.getByLabelText(/Branches/), "release");
    await user.click(screen.getByRole("button", { name: "Create target" }));

    expect(createMock).toHaveBeenCalledTimes(1);
    expect(createMock.mock.calls[0][0]).toMatchObject({
      name: "App repo",
      config: { branch: "release" },
    });
  });
});
