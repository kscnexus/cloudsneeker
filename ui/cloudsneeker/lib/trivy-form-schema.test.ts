import { describe, expect, it } from "vitest";

import {
  buildTrivyConfig,
  CODE_ARCHIVE_ACCEPT,
  isSupportedCodeArchive,
  readsRepository,
  SAST_MAX_EXCLUDE_PATTERNS,
  SAST_SOURCE,
  toggleSastRuleset,
  trivyTargetFormSchema,
} from "@/cloudsneeker/lib/trivy-form-schema";
import {
  defaultScannersForMode,
  labelForProviderType,
  SAST_RULESET_OPTIONS,
  scannersForMode,
  scannersForModeFrom,
  TRIVY_MODE_OPTIONS,
} from "@/cloudsneeker/lib/trivy-modes";
import { TRIVY_MODE } from "@/cloudsneeker/types/trivy";

describe("trivyTargetFormSchema", () => {
  it("requires repository URL for repo mode", () => {
    const result = trivyTargetFormSchema.safeParse({
      name: "repo-scan",
      mode: TRIVY_MODE.REPO,
      providerId: "11111111-1111-4111-8111-111111111111",
      repositoryUrl: "",
    });
    expect(result.success).toBe(false);
  });

  it("builds config for sbom mode", () => {
    const values = trivyTargetFormSchema.parse({
      name: "sbom-scan",
      mode: TRIVY_MODE.SBOM,
      providerId: "11111111-1111-4111-8111-111111111111",
      sbom: '{"bomFormat":"CycloneDX"}',
      scanners: ["vuln"],
    });
    expect(buildTrivyConfig(values)).toEqual({
      scanners: ["vuln"],
      sbom: '{"bomFormat":"CycloneDX"}',
    });
  });
});

describe("repository targets", () => {
  const repo = {
    name: "app-repo",
    mode: TRIVY_MODE.REPO,
    providerId: "11111111-1111-4111-8111-111111111111",
    repositoryUrl: "https://github.com/acme/app",
  };

  it("is the first mode and is labelled as a full code repository", () => {
    expect(TRIVY_MODE_OPTIONS[0]).toMatchObject({
      value: TRIVY_MODE.REPO,
      label: "Code repository",
      providerTypes: ["iac"],
    });
    expect(labelForProviderType("iac")).toBe("Code repository");
  });

  it("runs every repository scanner by default, IaC included", () => {
    expect(buildTrivyConfig(trivyTargetFormSchema.parse(repo))).toEqual({
      scanners: ["vuln", "misconfig", "secret", "license"],
      repository_url: "https://github.com/acme/app",
    });
  });

  it("saves only the selected scan types in canonical order", () => {
    const values = trivyTargetFormSchema.parse({
      ...repo,
      scanners: ["license", "vuln"],
    });
    expect(buildTrivyConfig(values).scanners).toEqual(["vuln", "license"]);
  });
});

describe("scan types per mode", () => {
  const providerId = "11111111-1111-4111-8111-111111111111";

  it.each([
    [TRIVY_MODE.REPO, ["vuln", "misconfig", "secret", "license"]],
    [TRIVY_MODE.FS, ["vuln", "misconfig", "secret", "license"]],
    [TRIVY_MODE.SBOM, ["vuln", "license"]],
    [TRIVY_MODE.K8S, ["vuln", "misconfig", "secret", "rbac"]],
    [TRIVY_MODE.IAC, ["vuln", "misconfig", "secret", "license"]],
    [TRIVY_MODE.IMAGE, ["vuln", "misconfig", "secret", "license"]],
    [TRIVY_MODE.ROOTFS, ["vuln", "misconfig", "secret", "license"]],
    [TRIVY_MODE.SAST, []],
  ] as const)("%s supports %j", (mode, scanners) => {
    expect(scannersForMode(mode)).toEqual(scanners);
    for (const name of defaultScannersForMode(mode)) {
      expect(scanners).toContain(name);
    }
  });

  it("rejects scan types the mode does not support", () => {
    const result = trivyTargetFormSchema.safeParse({
      name: "sbom-scan",
      mode: TRIVY_MODE.SBOM,
      providerId,
      sbom: "{}",
      scanners: ["vuln", "secret"],
    });
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]).toMatchObject({
      path: ["scanners"],
      message: "This mode does not support: Secrets.",
    });
  });

  it("requires at least one scan type", () => {
    const result = trivyTargetFormSchema.safeParse({
      name: "k8s-scan",
      mode: TRIVY_MODE.K8S,
      providerId,
      scanners: [],
    });
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.path).toEqual(["scanners"]);
  });

  it("saves the selected scan types for repository policy and image modes", () => {
    // Every mode runs on the scan engine, which honours the selection.
    for (const mode of [TRIVY_MODE.IAC, TRIVY_MODE.IMAGE]) {
      const values = trivyTargetFormSchema.parse({
        name: "scan",
        mode,
        providerId,
        scanners: ["vuln"],
      });
      expect(buildTrivyConfig(values)).toEqual({ scanners: ["vuln"] });
    }
    expect(defaultScannersForMode(TRIVY_MODE.IAC)).toEqual([
      "vuln",
      "misconfig",
      "secret",
    ]);
  });

  it("requires an archive for the root filesystem mode", () => {
    const missing = trivyTargetFormSchema.safeParse({
      name: "rootfs-scan",
      mode: TRIVY_MODE.ROOTFS,
      providerId,
    });
    expect(missing.success).toBe(false);
    const values = trivyTargetFormSchema.parse({
      name: "rootfs-scan",
      mode: TRIVY_MODE.ROOTFS,
      providerId,
      archiveB64: "UEsDBA==",
    });
    expect(buildTrivyConfig(values).archive_b64).toBe("UEsDBA==");
  });

  it("saves the scan profile and keeps option overrides on edit", () => {
    const values = trivyTargetFormSchema.parse({
      name: "repo-scan",
      mode: TRIVY_MODE.REPO,
      providerId,
      repositoryUrl: "https://git.example.com/acme/shop",
      profile: "builtin:full",
      // A profile decides the scan types, so an empty list is accepted.
      scanners: [],
    });
    expect(
      buildTrivyConfig(values, { options: { skip_dirs: ["vendor"] } }),
    ).toEqual({
      options: { skip_dirs: ["vendor"] },
      scanners: [],
      profile: "builtin:full",
      repository_url: "https://git.example.com/acme/shop",
    });
    const without = trivyTargetFormSchema.parse({
      name: "repo-scan",
      mode: TRIVY_MODE.REPO,
      providerId,
      repositoryUrl: "https://git.example.com/acme/shop",
    });
    expect(buildTrivyConfig(without)).not.toHaveProperty("profile");
  });

  it("drops scanners saved before each mode had its own list", () => {
    expect(
      scannersForModeFrom(TRIVY_MODE.SBOM, ["vuln", "misconfig", "secret"]),
    ).toEqual(["vuln"]);
    expect(scannersForModeFrom(TRIVY_MODE.SBOM, ["secret"])).toEqual(["vuln"]);
    expect(scannersForModeFrom(TRIVY_MODE.K8S, ["rbac", "vuln"])).toEqual([
      "vuln",
      "rbac",
    ]);
  });
});

describe("static analysis (SAST) targets", () => {
  const base = {
    name: "app-code",
    mode: TRIVY_MODE.SAST,
    providerId: "11111111-1111-4111-8111-111111111111",
  };

  it("builds the repository config the API validates", () => {
    const values = trivyTargetFormSchema.parse({
      ...base,
      repositoryUrl: " https://github.com/acme/app ",
      rulesets: ["python", "javascript"],
      exclude: "tests/**\n\n**/*.min.js\ntests/**",
    });
    expect(buildTrivyConfig(values)).toEqual({
      repository_url: "https://github.com/acme/app",
      rulesets: ["python", "javascript"],
      exclude: ["tests/**", "**/*.min.js"],
    });
  });

  it("defaults to language detection and sends no scanner list", () => {
    const config = buildTrivyConfig(
      trivyTargetFormSchema.parse({
        ...base,
        repositoryUrl: "https://github.com/acme/app",
      }),
    );
    expect(config).toEqual({
      repository_url: "https://github.com/acme/app",
      rulesets: ["auto"],
      exclude: [],
    });
    expect(config).not.toHaveProperty("scanners");
  });

  it("uses the uploaded archive instead of a repository", () => {
    const values = trivyTargetFormSchema.parse({
      ...base,
      sastSource: SAST_SOURCE.ARCHIVE,
      repositoryUrl: "https://github.com/acme/ignored",
      archiveB64: "UEsDBA==",
    });
    expect(buildTrivyConfig(values)).toEqual({
      archive_b64: "UEsDBA==",
      rulesets: ["auto"],
      exclude: [],
    });
  });

  it("requires the selected code source", () => {
    expect(trivyTargetFormSchema.safeParse(base).success).toBe(false);
    const archive = trivyTargetFormSchema.safeParse({
      ...base,
      sastSource: SAST_SOURCE.ARCHIVE,
    });
    expect(archive.success).toBe(false);
    expect(archive.error?.issues[0]?.path).toEqual(["archiveB64"]);
  });

  it("rejects unknown and conflicting rule packs", () => {
    const repo = { ...base, repositoryUrl: "https://github.com/acme/app" };
    expect(
      trivyTargetFormSchema.safeParse({ ...repo, rulesets: ["ruby"] }).success,
    ).toBe(false);
    expect(
      trivyTargetFormSchema.safeParse({ ...repo, rulesets: ["auto", "go"] })
        .success,
    ).toBe(false);
    expect(
      trivyTargetFormSchema.safeParse({ ...repo, rulesets: ["all"] }).success,
    ).toBe(true);
  });

  it("bounds exclude patterns like the API", () => {
    const repo = { ...base, repositoryUrl: "https://github.com/acme/app" };
    const tooMany = Array.from(
      { length: SAST_MAX_EXCLUDE_PATTERNS + 1 },
      (_, index) => `dir${index}/**`,
    ).join("\n");
    expect(
      trivyTargetFormSchema.safeParse({ ...repo, exclude: tooMany }).success,
    ).toBe(false);
    expect(
      trivyTargetFormSchema.safeParse({ ...repo, exclude: "a".repeat(201) })
        .success,
    ).toBe(false);
  });

  it("keeps auto and all exclusive when toggling rule packs", () => {
    expect(toggleSastRuleset(["auto"], "python")).toEqual(["python"]);
    expect(toggleSastRuleset(["python"], "go")).toEqual(["python", "go"]);
    expect(toggleSastRuleset(["python", "go"], "all")).toEqual(["all"]);
    expect(toggleSastRuleset(["python"], "python")).toEqual(["auto"]);
  });

  it("is offered as an Application Security mode for repository sources", () => {
    const option = TRIVY_MODE_OPTIONS.find(
      (item) => item.value === TRIVY_MODE.SAST,
    );
    expect(option).toMatchObject({
      label: "Static analysis (SAST)",
      providerTypes: ["iac"],
    });
    expect(SAST_RULESET_OPTIONS.map((item) => item.value)).toEqual([
      "auto",
      "all",
      "csharp",
      "go",
      "java",
      "javascript",
      "python",
      "scala",
    ]);
  });
});

describe("code archive formats", () => {
  it("lists ZIP and TAR variants for the file input", () => {
    expect(CODE_ARCHIVE_ACCEPT).toBe(".zip,.tar,.tar.gz,.tgz,.tar.bz2,.tar.xz");
  });

  it.each([
    "app.zip",
    "app.tar",
    "App.TAR.GZ",
    "app.tgz",
    "a.tar.bz2",
    "a.tar.xz",
  ])("accepts %s", (name) => {
    expect(isSupportedCodeArchive(name)).toBe(true);
  });

  it.each(["app.7z", "app.rar", "app.gz", "app.json", ""])(
    "rejects %s",
    (name) => {
      expect(isSupportedCodeArchive(name)).toBe(false);
    },
  );
});

describe("branches", () => {
  const base = {
    name: "shop",
    providerId: "11111111-1111-4111-8111-111111111111",
    repositoryUrl: "git@bitbucket.org:acme/shop.git",
  };

  it("saves the branch on repository targets", () => {
    const values = trivyTargetFormSchema.parse({
      ...base,
      mode: TRIVY_MODE.REPO,
      branches: ["develop"],
    });
    expect(buildTrivyConfig(values).branch).toBe("develop");
    expect(buildTrivyConfig(values, {}, "release").branch).toBe("release");
  });

  it("saves the branch on static analysis targets that read Git", () => {
    const values = trivyTargetFormSchema.parse({
      ...base,
      mode: TRIVY_MODE.SAST,
      branches: ["develop"],
    });
    expect(buildTrivyConfig(values)).toMatchObject({
      repository_url: base.repositoryUrl,
      branch: "develop",
    });
  });

  it("leaves the branch out for the default branch and archives", () => {
    const repo = trivyTargetFormSchema.parse({
      ...base,
      mode: TRIVY_MODE.REPO,
    });
    expect(buildTrivyConfig(repo)).not.toHaveProperty("branch");
    const archive = trivyTargetFormSchema.parse({
      ...base,
      mode: TRIVY_MODE.SAST,
      sastSource: SAST_SOURCE.ARCHIVE,
      archiveB64: "UEsDBA==",
      branches: ["develop"],
    });
    expect(buildTrivyConfig(archive)).not.toHaveProperty("branch");
  });

  it("knows which forms read a repository", () => {
    expect(readsRepository(TRIVY_MODE.REPO, undefined)).toBe(true);
    expect(readsRepository(TRIVY_MODE.SAST, SAST_SOURCE.REPOSITORY)).toBe(true);
    expect(readsRepository(TRIVY_MODE.SAST, SAST_SOURCE.ARCHIVE)).toBe(false);
    expect(readsRepository(TRIVY_MODE.IMAGE, undefined)).toBe(false);
  });
});
