import { describe, expect, it } from "vitest";

import { groupSourceOptions, sourceOption } from "./source-options";

const repo = (id: string, name: string) =>
  sourceOption({ id, attributes: { provider: "iac", alias: name } });

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
      label: "Kubernetes · 123",
    });
  });
});

describe("groupSourceOptions", () => {
  const options = [
    repo("r1", "acme/web"),
    repo("r2", "acme/api"),
    repo("r3", "solo/tool"),
    sourceOption({
      id: "k",
      attributes: { provider: "kubernetes", alias: "prod" },
    }),
  ];

  it("puts imported repositories under their GitHub connection", () => {
    const groups = groupSourceOptions(options, [
      { id: "c1", label: "acme", repositoryIds: ["r1", "r2", "missing"] },
    ]);
    expect(groups.map((group) => group.label)).toEqual([
      "GitHub · acme",
      "Other code repository sources",
      "Kubernetes",
    ]);
    expect(groups[0].options.map((option) => option.label)).toEqual([
      "acme/api",
      "acme/web",
    ]);
    expect(groups[1].options.map((option) => option.id)).toEqual(["r3"]);
  });

  it("groups by type when there are no connections", () => {
    const groups = groupSourceOptions(options);
    expect(groups.map((group) => group.label)).toEqual([
      "Code repository",
      "Kubernetes",
    ]);
    expect(groups[0].options).toHaveLength(3);
  });

  it("skips connections with no listed repository", () => {
    expect(
      groupSourceOptions(
        [repo("r1", "x/y")],
        [{ id: "c1", label: "acme", repositoryIds: [] }],
      ).map((group) => group.label),
    ).toEqual(["Code repository"]);
  });
});
