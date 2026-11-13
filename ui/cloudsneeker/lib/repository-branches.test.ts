import { describe, expect, it } from "vitest";

import {
  branchDisplay,
  branchTargetName,
  targetsForBranches,
  toRepositoryBranchList,
} from "@/cloudsneeker/lib/repository-branches";

describe("branchTargetName", () => {
  it("adds the branch to the target name", () => {
    expect(branchTargetName("shop", "develop")).toBe("shop @ develop");
  });

  it("keeps names that already end with the branch", () => {
    expect(branchTargetName("shop @ develop", "develop")).toBe(
      "shop @ develop",
    );
    expect(branchTargetName("shop (develop)", "develop")).toBe(
      "shop (develop)",
    );
    expect(branchTargetName("shop", "  ")).toBe("shop");
  });
});

describe("targetsForBranches", () => {
  it("scans the default branch when none is picked", () => {
    expect(targetsForBranches("shop", [])).toEqual([
      { name: "shop", branch: "" },
    ]);
  });

  it("keeps the name for a single branch", () => {
    expect(targetsForBranches("shop", ["develop"])).toEqual([
      { name: "shop", branch: "develop" },
    ]);
  });

  it("makes one uniquely named target per branch", () => {
    expect(
      targetsForBranches("shop", ["main", " develop ", "main", ""]),
    ).toEqual([
      { name: "shop @ main", branch: "main" },
      { name: "shop @ develop", branch: "develop" },
    ]);
  });
});

describe("branchDisplay", () => {
  it("names the default branch when none is set", () => {
    expect(branchDisplay("")).toBe("Default branch");
    expect(branchDisplay(undefined)).toBe("Default branch");
    expect(branchDisplay("release/1.0")).toBe("release/1.0");
  });
});

describe("toRepositoryBranchList", () => {
  it("reads the API document", () => {
    expect(
      toRepositoryBranchList({
        data: [
          {
            id: "main",
            type: "cloudsneeker-appsec-branches",
            attributes: { name: "main", default: true },
          },
          {
            id: "develop",
            type: "cloudsneeker-appsec-branches",
            attributes: { name: "develop", default: false },
          },
        ],
        meta: { default_branch: "main", truncated: true, count: 2 },
      }),
    ).toEqual({
      branches: ["main", "develop"],
      defaultBranch: "main",
      truncated: true,
    });
  });

  it("returns null for errors and malformed bodies", () => {
    expect(toRepositoryBranchList({ error: "refused" })).toBeNull();
    expect(toRepositoryBranchList(undefined)).toBeNull();
    expect(toRepositoryBranchList({ data: {} })).toBeNull();
  });
});
