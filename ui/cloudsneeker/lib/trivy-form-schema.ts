import { z } from "zod";

import {
  defaultScannersForMode,
  hasFixedScanners,
  labelForTrivyScanner,
  scannersForMode,
} from "@/cloudsneeker/lib/trivy-modes";
import {
  SAST_RULESET,
  type SastRuleset,
  TRIVY_MODE,
  TRIVY_SCANNER,
  type TrivyMode,
} from "@/cloudsneeker/types/trivy";

/** Where a SAST target reads its code from. */
export const SAST_SOURCE = {
  REPOSITORY: "repository",
  ARCHIVE: "archive",
} as const;

export type SastSource = (typeof SAST_SOURCE)[keyof typeof SAST_SOURCE];

// Bounds from `validate_sast_config` (`services/sast.py`).
export const SAST_MAX_EXCLUDE_PATTERNS = 50;
export const SAST_MAX_EXCLUDE_LENGTH = 200;

const SAST_RULESET_VALUES = Object.values(SAST_RULESET);
const TRIVY_SCANNER_VALUES = Object.values(TRIVY_SCANNER);

/** Code archive formats the scan worker can unpack. */
export const CODE_ARCHIVE_EXTENSIONS = [
  ".zip",
  ".tar",
  ".tar.gz",
  ".tgz",
  ".tar.bz2",
  ".tar.xz",
] as const;

/** `accept` value for the code archive file inputs. */
export const CODE_ARCHIVE_ACCEPT = CODE_ARCHIVE_EXTENSIONS.join(",");

export const CODE_ARCHIVE_HELP =
  "ZIP or TAR archive (7-Zip and RAR are not supported)";

export const isSupportedCodeArchive = (fileName: string): boolean => {
  const lower = fileName.trim().toLowerCase();
  return CODE_ARCHIVE_EXTENSIONS.some((extension) => lower.endsWith(extension));
};

export const parseExcludePatterns = (value: string): string[] =>
  Array.from(
    new Set(
      value
        .split(/\r?\n/)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  );

/** Modes that scan an uploaded archive. */
export const isArchiveMode = (mode: TrivyMode): boolean =>
  mode === TRIVY_MODE.FS || mode === TRIVY_MODE.ROOTFS;

export const trivyTargetFormSchema = z
  .object({
    name: z.string().trim().min(3).max(100),
    description: z.string().max(2000).optional().default(""),
    mode: z.enum([
      TRIVY_MODE.IAC,
      TRIVY_MODE.IMAGE,
      TRIVY_MODE.FS,
      TRIVY_MODE.REPO,
      TRIVY_MODE.SBOM,
      TRIVY_MODE.K8S,
      TRIVY_MODE.SAST,
      TRIVY_MODE.ROOTFS,
    ]),
    providerId: z.uuid(),
    scanners: z
      .array(z.enum(TRIVY_SCANNER_VALUES))
      .optional()
      .default(defaultScannersForMode(TRIVY_MODE.REPO)),
    images: z.string().optional().default(""),
    repositoryUrl: z.string().optional().default(""),
    /**
     * Branches to scan; empty scans the repository's default branch. A new
     * target with several branches is saved as one target per branch.
     */
    branches: z.array(z.string().trim().min(1).max(200)).optional().default([]),
    archiveB64: z.string().optional().default(""),
    sbom: z.string().optional().default(""),
    namespace: z.string().optional().default(""),
    /** `builtin:<key>` or a scan profile id; empty uses the defaults. */
    profile: z.string().optional().default(""),
    /** Application the target belongs to; empty leaves it unassigned. */
    applicationId: z.string().optional().default(""),
    sastSource: z
      .enum([SAST_SOURCE.REPOSITORY, SAST_SOURCE.ARCHIVE])
      .optional()
      .default(SAST_SOURCE.REPOSITORY),
    rulesets: z
      .array(z.enum(SAST_RULESET_VALUES))
      .optional()
      .default([SAST_RULESET.AUTO]),
    exclude: z.string().optional().default(""),
    scheduleEnabled: z.boolean().optional().default(false),
    scheduleCron: z.string().optional().default(""),
    scheduleTimezone: z.string().optional().default("UTC"),
  })
  .superRefine((values, ctx) => {
    // A scan profile decides the scanners; the list is then not used.
    if (
      values.mode !== TRIVY_MODE.SAST &&
      !hasFixedScanners(values.mode) &&
      !values.profile
    ) {
      const allowed = scannersForMode(values.mode);
      const unsupported = values.scanners.filter(
        (name) => !allowed.includes(name),
      );
      if (values.scanners.length === 0) {
        ctx.addIssue({
          code: "custom",
          path: ["scanners"],
          message: "Select at least one scan type.",
        });
      } else if (unsupported.length > 0) {
        ctx.addIssue({
          code: "custom",
          path: ["scanners"],
          message: `This mode does not support: ${unsupported.map(labelForTrivyScanner).join(", ")}.`,
        });
      }
    }
    if (values.mode === TRIVY_MODE.REPO && !values.repositoryUrl.trim()) {
      ctx.addIssue({
        code: "custom",
        path: ["repositoryUrl"],
        message: "Repository URL is required for repo mode.",
      });
    }
    if (isArchiveMode(values.mode) && !values.archiveB64.trim()) {
      ctx.addIssue({
        code: "custom",
        path: ["archiveB64"],
        message: "Upload a zip or tar archive for filesystem mode.",
      });
    }
    if (values.mode === TRIVY_MODE.SBOM && !values.sbom.trim()) {
      ctx.addIssue({
        code: "custom",
        path: ["sbom"],
        message: "SBOM content is required for sbom mode.",
      });
    }
    if (values.mode === TRIVY_MODE.SAST) {
      if (
        values.sastSource === SAST_SOURCE.REPOSITORY &&
        !values.repositoryUrl.trim()
      ) {
        ctx.addIssue({
          code: "custom",
          path: ["repositoryUrl"],
          message: "Repository URL is required for static analysis.",
        });
      }
      if (
        values.sastSource === SAST_SOURCE.ARCHIVE &&
        !values.archiveB64.trim()
      ) {
        ctx.addIssue({
          code: "custom",
          path: ["archiveB64"],
          message: "Upload a zip or tar archive of the code.",
        });
      }
      const exclusive = values.rulesets.filter(
        (name) => name === SAST_RULESET.AUTO || name === SAST_RULESET.ALL,
      );
      if (
        exclusive.length > 0 &&
        (exclusive.length > 1 || values.rulesets.length > 1)
      ) {
        ctx.addIssue({
          code: "custom",
          path: ["rulesets"],
          message:
            "Detect languages and All languages cannot be combined with other rule packs.",
        });
      }
      const patterns = parseExcludePatterns(values.exclude);
      if (patterns.length > SAST_MAX_EXCLUDE_PATTERNS) {
        ctx.addIssue({
          code: "custom",
          path: ["exclude"],
          message: `At most ${SAST_MAX_EXCLUDE_PATTERNS} exclude patterns are allowed.`,
        });
      }
      if (
        patterns.some((pattern) => pattern.length > SAST_MAX_EXCLUDE_LENGTH)
      ) {
        ctx.addIssue({
          code: "custom",
          path: ["exclude"],
          message: `Each exclude pattern must be at most ${SAST_MAX_EXCLUDE_LENGTH} characters.`,
        });
      }
    }
    if (values.scheduleEnabled && !values.scheduleCron.trim()) {
      ctx.addIssue({
        code: "custom",
        path: ["scheduleCron"],
        message: "Cron is required when the schedule is enabled.",
      });
    }
  });

export type TrivyTargetFormInput = z.input<typeof trivyTargetFormSchema>;
export type TrivyTargetFormValues = z.output<typeof trivyTargetFormSchema>;

/** Scanners saved for a mode; fixed-scanner modes always run their full set. */
const scannersToSave = (
  mode: TrivyMode,
  selected: readonly string[],
): string[] => {
  if (hasFixedScanners(mode)) return defaultScannersForMode(mode);
  return scannersForMode(mode).filter((name) => selected.includes(name));
};

/** True when the form reads a Git repository (so a branch applies). */
export const readsRepository = (
  mode: TrivyMode,
  sastSource: SastSource | undefined,
): boolean =>
  mode === TRIVY_MODE.REPO ||
  (mode === TRIVY_MODE.SAST && sastSource !== SAST_SOURCE.ARCHIVE);

/**
 * Target config from the form. `preserved` holds saved keys the form does
 * not edit (scan option overrides), so an edit does not drop them. `branch`
 * is the one branch this target scans (the first selected by default).
 */
export const buildTrivyConfig = (
  values: TrivyTargetFormValues,
  preserved: Record<string, unknown> = {},
  branch: string = values.branches[0] ?? "",
): Record<string, unknown> => {
  const branchConfig =
    readsRepository(values.mode, values.sastSource) && branch.trim()
      ? { branch: branch.trim() }
      : {};
  if (values.mode === TRIVY_MODE.SAST) {
    // The static analysis engine has no scanner list; sending one is ignored.
    const source =
      values.sastSource === SAST_SOURCE.ARCHIVE
        ? { archive_b64: values.archiveB64.trim() }
        : { repository_url: values.repositoryUrl.trim(), ...branchConfig };
    return {
      ...source,
      rulesets:
        values.rulesets.length > 0 ? values.rulesets : [SAST_RULESET.AUTO],
      exclude: parseExcludePatterns(values.exclude),
    };
  }
  const config: Record<string, unknown> = {
    ...preserved,
    scanners: scannersToSave(values.mode, values.scanners),
  };
  if (values.profile) config.profile = values.profile;

  if (values.mode === TRIVY_MODE.IMAGE) {
    const images = values.images
      .split(/[\n,]/)
      .map((item) => item.trim())
      .filter(Boolean);
    if (images.length > 0) {
      config.images = images;
    }
  }
  if (values.mode === TRIVY_MODE.REPO) {
    config.repository_url = values.repositoryUrl.trim();
    Object.assign(config, branchConfig);
  }
  if (isArchiveMode(values.mode)) {
    if (values.archiveB64.trim()) {
      config.archive_b64 = values.archiveB64.trim();
    }
  }
  if (values.mode === TRIVY_MODE.SBOM) {
    config.sbom = values.sbom;
  }
  if (values.mode === TRIVY_MODE.K8S && values.namespace.trim()) {
    config.namespace = values.namespace.trim();
  }
  return config;
};

const EXCLUSIVE_RULESETS: readonly SastRuleset[] = [
  SAST_RULESET.AUTO,
  SAST_RULESET.ALL,
];

/** Next ruleset selection: auto / all stand alone; languages combine. */
export const toggleSastRuleset = (
  current: readonly SastRuleset[],
  value: SastRuleset,
): SastRuleset[] => {
  if (current.includes(value)) {
    const next = current.filter((item) => item !== value);
    return next.length > 0 ? next : [SAST_RULESET.AUTO];
  }
  if (EXCLUSIVE_RULESETS.includes(value)) return [value];
  return [
    ...current.filter((item) => !EXCLUSIVE_RULESETS.includes(item)),
    value,
  ];
};
