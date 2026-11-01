// Builds the CycloneDX documents an SBOM target scans, from dependency
// manifests or from components Seeker AI pulls out of a description.

export const SBOM_ECOSYSTEM = {
  NPM: "npm",
  PYPI: "pypi",
  MAVEN: "maven",
  GOLANG: "golang",
  NUGET: "nuget",
  GEM: "gem",
  CARGO: "cargo",
  COMPOSER: "composer",
} as const;

export type SbomEcosystem =
  (typeof SBOM_ECOSYSTEM)[keyof typeof SBOM_ECOSYSTEM];

export const SBOM_ECOSYSTEMS = Object.values(SBOM_ECOSYSTEM);

export interface SbomComponent {
  name: string;
  version: string;
  ecosystem: SbomEcosystem;
}

/** Longest plain-language description Seeker AI reads. */
export const SBOM_DESCRIPTION_MAX_LENGTH = 4000;

/** Most components one generated document carries. */
export const SBOM_MAX_COMPONENTS = 500;

/** Dependency files the upload converts to an SBOM. */
export const SBOM_MANIFEST_FILES = [
  "package.json",
  "requirements.txt",
  "go.mod",
] as const;

export const SBOM_UPLOAD_ACCEPT = ".json,.xml,.txt,.mod,.cdx,.spdx";

const isSbomEcosystem = (value: string): value is SbomEcosystem =>
  (SBOM_ECOSYSTEMS as readonly string[]).includes(value);

/** Package URL (purl) the scanner matches against advisories. */
export const purlFor = ({
  name,
  version,
  ecosystem,
}: SbomComponent): string => {
  const at = `@${encodeURIComponent(version)}`;
  if (ecosystem === SBOM_ECOSYSTEM.MAVEN && name.includes(":")) {
    const [group, artifact] = name.split(":", 2);
    return `pkg:maven/${group}/${artifact}${at}`;
  }
  if (ecosystem === SBOM_ECOSYSTEM.NPM && name.startsWith("@")) {
    const [scope, pkg] = name.split("/", 2);
    return `pkg:npm/${encodeURIComponent(scope)}/${pkg}${at}`;
  }
  if (ecosystem === SBOM_ECOSYSTEM.PYPI) {
    return `pkg:pypi/${name.toLowerCase().replace(/[-_.]+/g, "-")}${at}`;
  }
  return `pkg:${ecosystem}/${name}${at}`;
};

/** Exact version from a manifest range (`^1.2.3` → `1.2.3`), or `null`. */
export const exactVersion = (raw: string | null | undefined): string | null => {
  const match = (raw ?? "").trim().match(/^[\^~=v>]*\s*(\d[\w.+-]*)/);
  return match ? match[1] : null;
};

const dedupe = (components: SbomComponent[]): SbomComponent[] => {
  const seen = new Set<string>();
  return components.filter((component) => {
    const key = purlFor(component);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};

/** CycloneDX 1.5 JSON for `components`, ready for an SBOM target. */
export const buildCycloneDxSbom = (
  components: readonly SbomComponent[],
  now: Date = new Date(),
): string => {
  const unique = dedupe([...components]).slice(0, SBOM_MAX_COMPONENTS);
  const document = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      timestamp: now.toISOString(),
      tools: { components: [{ type: "application", name: "Cloudsneeker" }] },
    },
    components: unique.map((component) => {
      const purl = purlFor(component);
      return {
        type: "library",
        "bom-ref": purl,
        name: component.name,
        version: component.version,
        purl,
      };
    }),
  };
  return JSON.stringify(document, null, 2);
};

/** True when `text` already is a CycloneDX or SPDX JSON document. */
export const isSbomDocument = (text: string): boolean => {
  const trimmed = text.trim();
  if (trimmed.startsWith("<")) return /cyclonedx|spdx/i.test(trimmed);
  try {
    const parsed = JSON.parse(trimmed) as Record<string, unknown>;
    return parsed.bomFormat === "CycloneDX" || "spdxVersion" in parsed;
  } catch {
    return false;
  }
};

export interface ParsedComponents {
  components: SbomComponent[];
  /** Entries left out because they carry no exact version. */
  skipped: string[];
}

const parsePackageJson = (text: string): ParsedComponents => {
  const parsed = JSON.parse(text) as Record<string, unknown>;
  const result: ParsedComponents = { components: [], skipped: [] };
  for (const field of ["dependencies", "devDependencies"]) {
    const deps = parsed[field];
    if (!deps || typeof deps !== "object") continue;
    for (const [name, range] of Object.entries(deps)) {
      const version = exactVersion(typeof range === "string" ? range : "");
      if (version) {
        result.components.push({
          name,
          version,
          ecosystem: SBOM_ECOSYSTEM.NPM,
        });
      } else {
        result.skipped.push(name);
      }
    }
  }
  return result;
};

const parseRequirements = (text: string): ParsedComponents => {
  const result: ParsedComponents = { components: [], skipped: [] };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split("#")[0].trim();
    if (!line || line.startsWith("-")) continue;
    const match = line.match(
      /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==\s*([\w.+!-]+)/,
    );
    if (match) {
      result.components.push({
        name: match[1],
        version: match[2],
        ecosystem: SBOM_ECOSYSTEM.PYPI,
      });
    } else {
      result.skipped.push(line.split(/[<>=~!;\s]/)[0]);
    }
  }
  return result;
};

const parseGoMod = (text: string): ParsedComponents => {
  const result: ParsedComponents = { components: [], skipped: [] };
  let inBlock = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split("//")[0].trim();
    if (line.startsWith("require (")) {
      inBlock = true;
      continue;
    }
    if (inBlock && line === ")") {
      inBlock = false;
      continue;
    }
    const entry = inBlock ? line : line.match(/^require\s+(.+)$/)?.[1];
    const match = entry?.match(/^(\S+)\s+(v[\w.+-]+)/);
    if (match) {
      result.components.push({
        name: match[1],
        version: match[2],
        ecosystem: SBOM_ECOSYSTEM.GOLANG,
      });
    }
  }
  return result;
};

/**
 * Components from a dependency manifest, chosen by file name, or `null`
 * for a file this parser does not read.
 */
export const parseManifest = (
  fileName: string,
  text: string,
): ParsedComponents | null => {
  const base = fileName.split(/[\\/]/).pop()?.toLowerCase() ?? "";
  if (base === "package.json") return parsePackageJson(text);
  if (base === "go.mod") return parseGoMod(text);
  if (/^requirements.*\.txt$/.test(base)) return parseRequirements(text);
  return null;
};

/** Valid components from untrusted (AI) output; the rest by name in `skipped`. */
export const sanitizeComponents = (items: unknown): ParsedComponents => {
  const result: ParsedComponents = { components: [], skipped: [] };
  if (!Array.isArray(items)) return result;
  for (const item of items) {
    if (!item || typeof item !== "object") continue;
    const { name, version, ecosystem } = item as Record<string, unknown>;
    if (typeof name !== "string" || !name.trim()) continue;
    const exact = exactVersion(typeof version === "string" ? version : "");
    const eco = typeof ecosystem === "string" ? ecosystem.toLowerCase() : "";
    if (!exact || !isSbomEcosystem(eco)) {
      result.skipped.push(name.trim());
      continue;
    }
    result.components.push({
      name: name.trim(),
      version: exact,
      ecosystem: eco,
    });
  }
  return result;
};

/** The JSON object in a model reply, tolerating a code fence or prose. */
export const extractJsonObject = (text: string): unknown => {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end <= start) return null;
  try {
    return JSON.parse(text.slice(start, end + 1));
  } catch {
    return null;
  }
};
