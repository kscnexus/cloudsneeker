import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { GithubRepositoriesForm } from "./github-repositories-form";

const { listMock, addMock } = vi.hoisted(() => ({
  listMock: vi.fn(),
  addMock: vi.fn(),
}));

vi.mock("@/cloudsneeker/actions/github-repositories", () => ({
  listGithubRepositories: listMock,
  addGithubRepositories: addMock,
}));

const CONNECTION = { id: "connection-1", account: "acme", alias: "Acme" };

interface RepoOptions {
  alreadyAdded?: boolean;
  archived?: boolean;
}

const repo = (fullName: string, options: RepoOptions = {}) => ({
  name: fullName.split("/")[1],
  full_name: fullName,
  repository_url: `https://github.com/${fullName}`,
  is_private: true,
  is_archived: Boolean(options.archived),
  default_branch: "main",
  updated_on: null,
  already_added: Boolean(options.alreadyAdded),
});

const list = async (user: ReturnType<typeof userEvent.setup>) => {
  await user.click(screen.getByRole("button", { name: "List repositories" }));
  return screen.findByRole("table");
};

describe("GithubRepositoriesForm", () => {
  beforeEach(() => {
    listMock.mockReset();
    addMock.mockReset();
  });

  it("points to the providers page when there is no GitHub connection", () => {
    render(<GithubRepositoriesForm connections={[]} />);

    expect(screen.getByText(/No GitHub connection yet/)).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "providers page" }),
    ).toHaveAttribute("href", "/providers");
  });

  it("lists the repositories of the connection and preselects new ones", async () => {
    const user = userEvent.setup();
    listMock.mockResolvedValue({
      repositories: [
        repo("acme/api"),
        repo("acme/web", { alreadyAdded: true }),
        repo("acme/old", { archived: true }),
      ],
      truncated: false,
    });
    render(<GithubRepositoriesForm connections={[CONNECTION]} />);

    const table = await list(user);

    expect(listMock).toHaveBeenCalledWith("connection-1");
    expect(
      within(table).getByRole("checkbox", { name: "Select acme/api" }),
    ).toBeChecked();
    expect(
      within(table).getByRole("checkbox", { name: "Select acme/web" }),
    ).toBeDisabled();
    expect(
      within(table).getByRole("checkbox", { name: "Select acme/old" }),
    ).not.toBeChecked();
    expect(within(table).getByText("Already added")).toBeInTheDocument();
  });

  it("adds the selected repositories without asking for a token", async () => {
    const user = userEvent.setup();
    listMock.mockResolvedValue({
      repositories: [repo("acme/api"), repo("acme/web")],
      truncated: false,
    });
    addMock.mockResolvedValue([
      {
        repositoryUrl: "https://github.com/acme/api",
        status: "added",
        providerId: "p1",
      },
    ]);
    render(<GithubRepositoriesForm connections={[CONNECTION]} />);
    const table = await list(user);

    await user.click(
      within(table).getByRole("checkbox", { name: "Select acme/web" }),
    );
    await user.click(screen.getByRole("button", { name: "Add 1 repository" }));

    expect(addMock).toHaveBeenCalledWith(
      [
        {
          full_name: "acme/api",
          repository_url: "https://github.com/acme/api",
        },
      ],
      { dailySchedule: true, timezone: expect.any(String) },
    );
    expect(
      await screen.findByText(
        /1 added, each with a code repository scan target/,
      ),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText(/token/i)).not.toBeInTheDocument();
  });

  it("adds without a schedule when daily scans are switched off", async () => {
    const user = userEvent.setup();
    listMock.mockResolvedValue({
      repositories: [repo("acme/api")],
      truncated: false,
    });
    addMock.mockResolvedValue([]);
    render(<GithubRepositoriesForm connections={[CONNECTION]} />);
    await list(user);

    await user.click(
      screen.getByRole("checkbox", {
        name: "Scan each added repository every day at 02:00",
      }),
    );
    await user.click(screen.getByRole("button", { name: "Add 1 repository" }));

    expect(addMock).toHaveBeenCalledWith(expect.any(Array), {
      dailySchedule: false,
      timezone: expect.any(String),
    });
  });

  it("shows why the listing failed", async () => {
    const user = userEvent.setup();
    listMock.mockResolvedValue({
      error: "The GitHub App is not installed on 'acme'.",
    });
    render(<GithubRepositoriesForm connections={[CONNECTION]} />);

    await user.click(screen.getByRole("button", { name: "List repositories" }));

    expect(
      await screen.findByText("The GitHub App is not installed on 'acme'."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });
});
