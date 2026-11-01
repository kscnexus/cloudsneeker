import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { BitbucketImportForm } from "./bitbucket-import-form";

const { listMock, importMock } = vi.hoisted(() => ({
  listMock: vi.fn(),
  importMock: vi.fn(),
}));

vi.mock("@/cloudsneeker/actions/bitbucket", () => ({
  listBitbucketRepositories: listMock,
  importBitbucketRepositories: importMock,
}));

const repo = (fullName: string, alreadyAdded = false) => ({
  name: fullName.split("/")[1],
  full_name: fullName,
  repository_url: `https://bitbucket.org/${fullName}.git`,
  html_url: `https://bitbucket.org/${fullName}`,
  ssh_url: `git@bitbucket.org:${fullName}.git`,
  project: "Platform",
  is_private: true,
  updated_on: null,
  already_added: alreadyAdded,
});

const fillCloud = async (user: ReturnType<typeof userEvent.setup>) => {
  await user.type(screen.getByLabelText("Workspace ID"), "acme");
  await user.type(screen.getByLabelText("Access token"), "tok");
};

describe("BitbucketImportForm", () => {
  beforeEach(() => {
    listMock.mockReset();
    importMock.mockReset();
  });

  it("keeps listing disabled until the workspace and token are set", async () => {
    const user = userEvent.setup();
    render(<BitbucketImportForm />);
    const list = screen.getByRole("button", { name: "List repositories" });

    expect(list).toBeDisabled();
    await fillCloud(user);
    expect(list).toBeEnabled();
  });

  it("shows the server URL field for Bitbucket Server", async () => {
    const user = userEvent.setup();
    render(<BitbucketImportForm />);

    expect(screen.queryByLabelText("Server URL")).not.toBeInTheDocument();
    await user.click(
      screen.getByRole("button", { name: "Bitbucket Data Center / Server" }),
    );
    expect(screen.getByLabelText("Server URL")).toBeInTheDocument();
    expect(screen.getByLabelText("Project key (optional)")).toBeInTheDocument();
  });

  it("offers the SSH key option before repositories are listed", async () => {
    const user = userEvent.setup();
    render(<BitbucketImportForm />);

    await user.click(screen.getByRole("button", { name: "SSH key" }));

    expect(screen.getByLabelText("SSH private key")).toBeInTheDocument();
    expect(listMock).not.toHaveBeenCalled();
  });

  it("shows the listing error", async () => {
    listMock.mockResolvedValue({ error: "Bitbucket rejected the token." });
    const user = userEvent.setup();
    render(<BitbucketImportForm />);

    await fillCloud(user);
    await user.click(screen.getByRole("button", { name: "List repositories" }));

    expect(
      await screen.findByText("Bitbucket rejected the token."),
    ).toBeInTheDocument();
  });

  it("lists repositories, preselects new ones and imports the selection", async () => {
    listMock.mockResolvedValue({
      repositories: [
        repo("acme/web"),
        repo("acme/api", true),
        repo("acme/infra"),
      ],
      cloneUsername: "",
      truncated: false,
    });
    importMock.mockResolvedValue([
      {
        repositoryUrl: "https://bitbucket.org/acme/web.git",
        status: "added",
        providerId: "p1",
      },
    ]);
    const user = userEvent.setup();
    render(<BitbucketImportForm />);

    await fillCloud(user);
    await user.click(screen.getByRole("button", { name: "List repositories" }));

    expect(await screen.findByText("acme/web")).toBeInTheDocument();
    expect(listMock).toHaveBeenCalledWith(
      expect.objectContaining({ workspace: "acme", accessToken: "tok" }),
    );
    expect(screen.getByLabelText("Select acme/api")).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Add 2 repositories" }),
    ).toBeEnabled();

    await user.click(screen.getByLabelText("Select acme/infra"));
    await user.click(screen.getByRole("button", { name: "Add 1 repository" }));

    expect(importMock).toHaveBeenCalledWith({
      repositories: [
        {
          repository_url: "https://bitbucket.org/acme/web.git",
          ssh_url: "git@bitbucket.org:acme/web.git",
          full_name: "acme/web",
        },
      ],
      cloneMethod: "token",
      accessToken: "tok",
      cloneUsername: "",
    });
    const row = screen.getByText("acme/web").closest("tr") as HTMLElement;
    expect(await within(row).findByText("Added")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Go to providers" }),
    ).toHaveAttribute("href", "/providers");
  });

  it("shows why a repository was not added", async () => {
    listMock.mockResolvedValue({
      repositories: [repo("acme/web")],
      cloneUsername: "",
      truncated: false,
    });
    importMock.mockResolvedValue([
      {
        repositoryUrl: "https://bitbucket.org/acme/web.git",
        status: "failed",
        message: "Your plan allows 3 providers.",
      },
    ]);
    const user = userEvent.setup();
    render(<BitbucketImportForm />);

    await fillCloud(user);
    await user.click(screen.getByRole("button", { name: "List repositories" }));
    await user.click(
      await screen.findByRole("button", { name: "Add 1 repository" }),
    );

    expect(
      await screen.findByText("Your plan allows 3 providers."),
    ).toBeInTheDocument();
    expect(screen.getByText(/1 not added/)).toBeInTheDocument();
  });

  it("imports with an SSH key once one is pasted", async () => {
    listMock.mockResolvedValue({
      repositories: [repo("acme/web")],
      cloneUsername: "",
      truncated: false,
    });
    importMock.mockResolvedValue([
      {
        repositoryUrl: "https://bitbucket.org/acme/web.git",
        status: "added",
        providerId: "p1",
      },
    ]);
    const user = userEvent.setup();
    render(<BitbucketImportForm />);

    await fillCloud(user);
    await user.click(screen.getByRole("button", { name: "List repositories" }));
    await user.click(await screen.findByRole("button", { name: "SSH key" }));

    const add = screen.getByRole("button", { name: "Add 1 repository" });
    expect(add).toBeDisabled();
    expect(screen.queryByLabelText("SSH host key")).not.toBeInTheDocument();

    await user.type(screen.getByLabelText("SSH private key"), "KEY");
    expect(add).toBeEnabled();
    await user.click(add);

    expect(importMock).toHaveBeenCalledWith(
      expect.objectContaining({
        cloneMethod: "ssh",
        sshKey: { privateKey: "KEY", passphrase: "", knownHosts: "" },
      }),
    );
  });
});
