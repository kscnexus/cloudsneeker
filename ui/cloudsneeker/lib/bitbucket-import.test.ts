import { describe, expect, it } from "vitest";

import { BITBUCKET_HOST } from "@/cloudsneeker/types/bitbucket";

import {
  buildListingBody,
  buildProviderBody,
  buildSecretBody,
  chunk,
  defaultSelection,
  filterRepositories,
  firstErrorDetail,
  isPlanLimitError,
  parseListing,
  repositoryAlias,
} from "./bitbucket-import";

const repo = (
  fullName: string,
  alreadyAdded = false,
  project = "Platform",
) => ({
  name: fullName.split("/")[1] ?? fullName,
  full_name: fullName,
  repository_url: `https://bitbucket.org/${fullName}.git`,
  html_url: `https://bitbucket.org/${fullName}`,
  project,
  is_private: true,
  updated_on: null,
  already_added: alreadyAdded,
});

describe("buildListingBody", () => {
  it("drops the server URL for Bitbucket Cloud and trims input", () => {
    expect(
      buildListingBody({
        host: BITBUCKET_HOST.CLOUD,
        workspace: " acme ",
        accessToken: " tok ",
        username: "",
        serverUrl: "https://ignored.example.com",
      }).data.attributes,
    ).toEqual({
      access_token: "tok",
      workspace: "acme",
      username: "",
      server_url: "",
    });
  });

  it("sends the server URL for Bitbucket Server", () => {
    expect(
      buildListingBody({
        host: BITBUCKET_HOST.SERVER,
        workspace: "",
        accessToken: "tok",
        username: "svc",
        serverUrl: "https://git.example.com ",
      }).data.attributes.server_url,
    ).toBe("https://git.example.com");
  });
});

describe("parseListing", () => {
  it("reads repositories and meta", () => {
    expect(
      parseListing({
        data: [{ attributes: repo("acme/web") }, { attributes: undefined }],
        meta: { clone_username: "x-bitbucket-api-token-auth", truncated: true },
      }),
    ).toEqual({
      repositories: [repo("acme/web")],
      cloneUsername: "x-bitbucket-api-token-auth",
      truncated: true,
    });
  });

  it("handles an empty document", () => {
    expect(parseListing({})).toEqual({
      repositories: [],
      cloneUsername: "",
      truncated: false,
    });
  });
});

describe("repositoryAlias", () => {
  it("keeps names the provider API accepts", () => {
    expect(repositoryAlias("acme/web")).toBe("acme/web");
    expect(repositoryAlias("a".repeat(150))).toHaveLength(100);
    expect(repositoryAlias("ab")).toBeUndefined();
  });
});

describe("buildProviderBody", () => {
  it("creates an IaC provider keyed by the clone URL", () => {
    expect(
      buildProviderBody("https://bitbucket.org/acme/web.git", "acme/web"),
    ).toEqual({
      data: {
        type: "providers",
        attributes: {
          provider: "iac",
          uid: "https://bitbucket.org/acme/web.git",
          alias: "acme/web",
        },
      },
    });
  });
});

describe("buildSecretBody", () => {
  it("stores the token and omits an empty username", () => {
    const body = buildSecretBody(
      "p1",
      "https://bitbucket.org/acme/web.git",
      "tok",
      "",
    );
    expect(body.data.attributes).toEqual({
      secret_type: "static",
      secret: {
        repository_url: "https://bitbucket.org/acme/web.git",
        access_token: "tok",
      },
    });
    expect(body.data.relationships.provider.data).toEqual({
      id: "p1",
      type: "providers",
    });
  });

  it("stores the clone username when the token needs one", () => {
    const body = buildSecretBody(
      "p1",
      "u",
      "tok",
      "x-bitbucket-api-token-auth",
    );
    expect(body.data.attributes.secret).toHaveProperty(
      "username",
      "x-bitbucket-api-token-auth",
    );
  });
});

describe("errors", () => {
  it("reads the first error detail", () => {
    expect(firstErrorDetail({ errors: [{ detail: "Nope" }] }, "fallback")).toBe(
      "Nope",
    );
    expect(firstErrorDetail(null, "fallback")).toBe("fallback");
  });

  it("detects the plan limit", () => {
    expect(isPlanLimitError({ errors: [{ code: "plan_limit_reached" }] })).toBe(
      true,
    );
    expect(isPlanLimitError({ errors: [{ code: "other" }] })).toBe(false);
    expect(isPlanLimitError(null)).toBe(false);
  });
});

describe("selection helpers", () => {
  const repositories = [
    repo("acme/web"),
    repo("acme/api", true),
    repo("acme/infra", false, "Ops"),
  ];

  it("selects only repositories not yet added", () => {
    expect(Array.from(defaultSelection(repositories))).toEqual([
      "https://bitbucket.org/acme/web.git",
      "https://bitbucket.org/acme/infra.git",
    ]);
  });

  it("filters by name or project", () => {
    expect(
      filterRepositories(repositories, "ops").map((r) => r.full_name),
    ).toEqual(["acme/infra"]);
    expect(filterRepositories(repositories, " ")).toHaveLength(3);
  });

  it("chunks a list", () => {
    expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
    expect(chunk([], 2)).toEqual([]);
  });
});
