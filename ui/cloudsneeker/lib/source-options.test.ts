import { describe, expect, it } from "vitest";

import {
  githubOwner,
  groupSourceOptions,
  sourceOption,
} from "./source-options";

const repo = (id: string, uid: string, alias?: string) =>
  sourceOption({ id, attributes: { provider: "iac", uid, alias } });

const github = (id: string, uid: string) =>
  sourceOption({ id, attributes: { provider: "github", uid } });

describe("sourceOption", () => {
  it("labels a provider with its type and alias, else its uid", () => {
    expect(
      sourceOption({
        id: "a",
        attributes: { provider: "kubernetes", uid: "123" },
      }),
    ).toEqual({
      id: "a",
      providerType: "kubernetes",
      uid: "123",
      label: "Kubernetes · 123",
    });
  });
});

describe("githubOwner", () => {
  it.each([
    ["https://github.com/Acme/web.git", "acme"],
    ["https://GitHub.com/acme/web", "acme"],
    ["git@github.com:acme/web.git", null],
    ["https://gitlab.com/acme/web", null],
    ["http://github.com/acme/web", null],
    ["not a url", null],
    [undefined, null],
  ])("reads %s as %s", (url, owner) => {
    expect(githubOwner(url)).toBe(owner);
  });
});

describe("groupSourceOptions", () => {
  const sources = [
    repo("r1", "https://github.com/acme/web.git", "acme/web"),
    repo("r2", "https://github.com/acme/api", "acme/api"),
    repo("r3", "https://github.com/solo/tool", "solo/tool"),
    repo("r4", "git@bitbucket.org:team/app.git", "team/app"),
    sourceOption({
      id: "k",
      attributes: { provider: "kubernetes", alias: "prod" },
    }),
  ];

  it("puts repositories under the GitHub connection of their owner", () => {
    const groups = groupSourceOptions(sources, [github("g1", "ACME")]);
    expect(groups.map((group) => group.label)).toEqual([
      "GitHub · ACME",
      "Other code repository sources",
      "Kubernetes",
    ]);
    expect(groups[0].options.map((option) => option.label)).toEqual([
      "acme/api",
      "acme/web",
    ]);
    expect(groups[1].options.map((option) => option.id)).toEqual(["r3", "r4"]);
  });

  it("groups by type when no owner is connected", () => {
    const groups = groupSourceOptions(sources);
    expect(groups.map((group) => group.label)).toEqual([
      "Code repository",
      "Kubernetes",
    ]);
    expect(groups[0].options).toHaveLength(4);
  });

  it("uses connections that are offered too", () => {
    const groups = groupSourceOptions([
      github("g1", "solo"),
      repo("r3", "https://github.com/solo/tool", "solo/tool"),
    ]);
    expect(groups[0]).toMatchObject({ label: "GitHub · solo" });
    expect(groups.map((group) => group.label)).toContain("GitHub");
  });
});
