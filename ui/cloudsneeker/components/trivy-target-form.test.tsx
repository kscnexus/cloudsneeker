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

// The form tests type whole values; on a loaded machine (commit hooks run
// many test files at once) they pass 5 s, and a timed-out test then leaks
// its create call into the next one.
describe("TrivyTargetForm", { timeout: 20_000 }, () => {
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
      "Misconfigurations",
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
          sast: { rulesets: ["auto"], exclude: [] },
        },
      }),
    );
  });

  it("runs static analysis in the repository target unless turned off", async () => {
    const user = userEvent.setup();
    createMock.mockResolvedValue({ data: { id: "t-1" } });
    render(<TrivyTargetForm providers={providers} />);

    expect(screen.getByLabelText(/Static analysis \(SAST\)/)).toBeChecked();
    expect(
      screen.getByRole("group", { name: "Rule packs" }),
    ).toBeInTheDocument();
    await user.type(screen.getByLabelText("Name"), "App repo");
    await user.type(
      screen.getByLabelText("Repository URL"),
      "https://github.com/acme/app",
    );
    await user.click(screen.getByLabelText(/Static analysis \(SAST\)/));
    await user.click(screen.getByRole("button", { name: "Create target" }));

    expect(createMock.mock.calls[0][0].config).not.toHaveProperty("sast");
  });

  it("lists the source's branches with the default first", async () => {
    render(<TrivyTargetForm providers={providers} />);

    const branch = await screen.findByRole("combobox", { name: /Main branch/ });
    expect(branchesMock).toHaveBeenCalledWith(
      "11111111-1111-4111-8111-111111111111",
    );
    const names = within(branch)
      .getAllByRole("option")
      .map((item) => item.textContent ?? "");
    expect(names[0]).toBe("Default branch (main)");
    expect(names).toContain("develop");
  });

  it("creates one target for the main branch and the other branches", async () => {
    const user = userEvent.setup();
    createMock.mockResolvedValue({ data: { id: "t-1" } });
    render(<TrivyTargetForm providers={providers} />);

    await user.type(screen.getByLabelText("Name"), "App repo");
    await user.type(
      screen.getByLabelText("Repository URL"),
      "git@bitbucket.org:acme/app.git",
    );
    await user.selectOptions(
      await screen.findByRole("combobox", { name: /Main branch/ }),
      "develop",
    );
    await user.type(
      screen.getByLabelText(/Other branches/),
      "release/*{enter}hotfix",
    );
    await user.click(screen.getByRole("button", { name: "Create target" }));

    expect(createMock).toHaveBeenCalledTimes(1);
    expect(createMock.mock.calls[0][0]).toMatchObject({
      name: "App repo",
      config: {
        repository_url: "git@bitbucket.org:acme/app.git",
        branch: "develop",
        branches: ["release/*", "hotfix"],
      },
    });
    expect(pushMock).toHaveBeenCalledWith("/application-security/t-1");
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
    await user.type(screen.getByLabelText(/Main branch/), "release");
    await user.click(screen.getByRole("button", { name: "Create target" }));

    expect(createMock).toHaveBeenCalledTimes(1);
    expect(createMock.mock.calls[0][0]).toMatchObject({
      name: "App repo",
      config: { branch: "release" },
    });
  });
});
