import { describe, expect, it } from "vitest";

import {
  TRIVY_MODE,
  type TrivyMode,
  type TrivyTargetResource,
} from "@/cloudsneeker/types/trivy";

import {
  planRepositoryScans,
  repositoryNameFromUrl,
  SCAN_ALL_REPO_PROFILE,
  scanAllTargetConfig,
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
  it("plans a code repository and a static analysis scan per repository", () => {
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
        mode: TRIVY_MODE.REPO,
      },
      {
        providerId: "p1",
        repositoryUrl: "git@bitbucket.org:acme/web.git",
        name: "acme/web (SAST)",
        mode: TRIVY_MODE.SAST,
      },
      {
        providerId: "p2",
        repositoryUrl: "git@bitbucket.org:acme/api.git",
        name: "acme/api",
        mode: TRIVY_MODE.REPO,
      },
      {
        providerId: "p2",
        repositoryUrl: "git@bitbucket.org:acme/api.git",
        name: "acme/api (SAST)",
        mode: TRIVY_MODE.SAST,
      },
    ]);
  });

  it("reuses existing targets of each type instead of creating them", () => {
    const plan = planRepositoryScans(
      [{ id: "p1", uid: "git@bitbucket.org:acme/web.git", alias: "acme/web" }],
      [
        target("t1", "p1", "Web deps"),
        target("t2", "p1", "Web code", TRIVY_MODE.SAST),
      ],
    );

    expect(plan.map((item) => [item.mode, item.targetId, item.name])).toEqual([
      [TRIVY_MODE.REPO, "t1", "Web deps"],
      [TRIVY_MODE.SAST, "t2", "Web code"],
    ]);
  });

  it("creates only the missing type, with a name unique per tenant", () => {
    const plan = planRepositoryScans(
      [{ id: "p1", uid: "git@bitbucket.org:acme/web.git", alias: "acme/web" }],
      [target("t1", "p1", "acme/web", TRIVY_MODE.SAST)],
    );

    expect(plan[0]).toMatchObject({ mode: TRIVY_MODE.REPO });
    expect(plan[0].targetId).toBeUndefined();
    expect(plan[0].name).toBe("acme/web (2)");
    expect(plan[1]).toMatchObject({ mode: TRIVY_MODE.SAST, targetId: "t1" });
  });

  it("keeps new names unique among themselves", () => {
    const plan = planRepositoryScans(
      [
        { id: "p1", uid: "git@bitbucket.org:acme/web.git", alias: "web" },
        { id: "p2", uid: "git@bitbucket.org:other/web.git", alias: "web" },
      ],
      [],
    );

    expect(plan.map((item) => item.name)).toEqual([
      "web",
      "web (SAST)",
      "web (2)",
      "web (SAST) (2)",
    ]);
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
    expect(plan[2].name).toHaveLength(100);
    expect(plan[3].name).toHaveLength(100);
  });
});

describe("scanAllTargetConfig", () => {
  const base = {
    providerId: "p1",
    repositoryUrl: "git@bitbucket.org:acme/web.git",
    name: "acme/web",
  };

  it("runs new code repository targets with every scanner", () => {
    expect(scanAllTargetConfig({ ...base, mode: TRIVY_MODE.REPO })).toEqual({
      repository_url: "git@bitbucket.org:acme/web.git",
      profile: SCAN_ALL_REPO_PROFILE,
    });
  });

  it("detects the languages of new static analysis targets", () => {
    expect(scanAllTargetConfig({ ...base, mode: TRIVY_MODE.SAST })).toEqual({
      repository_url: "git@bitbucket.org:acme/web.git",
      rulesets: ["auto"],
      exclude: [],
    });
  });
});

describe("summarizeScanResults", () => {
  it("counts started and failed scans", () => {
    expect(
      summarizeScanResults([
        { providerId: "p1", name: "a", mode: TRIVY_MODE.REPO, started: true },
        {
          providerId: "p2",
          name: "b",
          mode: TRIVY_MODE.SAST,
          started: false,
          message: "boom",
        },
        { providerId: "p3", name: "c", mode: TRIVY_MODE.REPO, started: true },
      ]),
    ).toEqual({ started: 2, failed: 1 });
  });
});
