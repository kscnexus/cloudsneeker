import { describe, expect, it } from "vitest";

import {
  buildTrivyConfig,
  SAST_MAX_EXCLUDE_PATTERNS,
  SAST_SOURCE,
  toggleSastRuleset,
  trivyTargetFormSchema,
} from "@/cloudsneeker/lib/trivy-form-schema";
import {
  SAST_RULESET_OPTIONS,
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
      scanners: "vuln",
    });
    expect(buildTrivyConfig(values)).toEqual({
      scanners: ["vuln"],
      sbom: '{"bomFormat":"CycloneDX"}',
    });
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
