import { describe, expect, it } from "vitest";

import {
  TRIVY_MODE,
  type TrivyMode,
  type TrivyTargetResource,
} from "@/cloudsneeker/types/trivy";

import {
  planRepositoryScans,
  repositoryNameFromUrl,
  summarizeScanResults,
} from "./app-security-scan-all";

const target = (
  id: string,
  providerId: string,
  name: string,
  mode: TrivyMode = TRIVY_MODE.REPO,
): TrivyTargetResource => ({
  id,
  type: "cloudsneeker-trivy-targets",
  attributes: {
    name,
    description: "",
    mode,
    config: {},
    provider_id: providerId,
  },
});

describe("repositoryNameFromUrl", () => {
  it.each([
    ["git@bitbucket.org:acme/web.git", "acme/web"],
    ["ssh://git@git.example.com:7999/plat/api.git", "plat/api"],
    ["https://bitbucket.org/acme/web.git", "acme/web"],
    ["https://github.com/acme/web/", "acme/web"],
    ["not a url", "not a url"],
  ])("reads %s as %s", (url, expected) => {
    expect(repositoryNameFromUrl(url)).toBe(expected);
  });
});

describe("planRepositoryScans", () => {
  it("creates a code repository target for each repository without one", () => {
    const plan = planRepositoryScans(
      [
        { id: "p1", uid: "git@bitbucket.org:acme/web.git", alias: "acme/web" },
        { id: "p2", uid: "git@bitbucket.org:acme/api.git", alias: null },
      ],
      [],
    );

    expect(plan).toEqual([
      {
        providerId: "p1",
        repositoryUrl: "git@bitbucket.org:acme/web.git",
        name: "acme/web",
      },
      {
        providerId: "p2",
        repositoryUrl: "git@bitbucket.org:acme/api.git",
        name: "acme/api",
      },
    ]);
  });

  it("reuses an existing code repository target instead of creating one", () => {
    const plan = planRepositoryScans(
      [{ id: "p1", uid: "git@bitbucket.org:acme/web.git", alias: "acme/web" }],
      [target("t1", "p1", "Web deps")],
    );

    expect(plan).toEqual([
      {
        providerId: "p1",
        repositoryUrl: "git@bitbucket.org:acme/web.git",
        name: "Web deps",
        targetId: "t1",
      },
    ]);
  });

  it("still creates a code repository target when only other modes exist", () => {
    const plan = planRepositoryScans(
      [{ id: "p1", uid: "git@bitbucket.org:acme/web.git", alias: "acme/web" }],
      [target("t1", "p1", "acme/web", TRIVY_MODE.SAST)],
    );

    expect(plan).toHaveLength(1);
    expect(plan[0].targetId).toBeUndefined();
    // Target names are unique per tenant.
    expect(plan[0].name).toBe("acme/web (2)");
  });

  it("keeps new names unique among themselves", () => {
    const plan = planRepositoryScans(
      [
        { id: "p1", uid: "git@bitbucket.org:acme/web.git", alias: "web" },
        { id: "p2", uid: "git@bitbucket.org:other/web.git", alias: "web" },
      ],
      [],
    );

    expect(plan.map((item) => item.name)).toEqual(["web", "web (2)"]);
  });

  it("fits names into the 3 to 100 character limit", () => {
    const long = `acme/${"x".repeat(120)}`;
    const plan = planRepositoryScans(
      [
        { id: "p1", uid: "git@bitbucket.org:a/b.git", alias: "ab" },
        { id: "p2", uid: `git@bitbucket.org:${long}.git`, alias: null },
      ],
      [],
    );

    expect(plan[0].name).toBe("Repository ab");
    expect(plan[1].name).toHaveLength(100);
  });
});

describe("summarizeScanResults", () => {
  it("counts started and failed scans", () => {
    expect(
      summarizeScanResults([
        { providerId: "p1", name: "a", started: true },
        { providerId: "p2", name: "b", started: false, message: "boom" },
        { providerId: "p3", name: "c", started: true },
      ]),
    ).toEqual({ started: 2, failed: 1 });
  });
});
