import {
  SAST_RULESET,
  TRIVY_MODE,
  TRIVY_SCANNER,
  type TrivyMode,
  type TrivyScanner,
} from "@/cloudsneeker/types/trivy";

export const TRIVY_MODE_OPTIONS = [
  {
    value: TRIVY_MODE.REPO,
    label: "Code repository",
    description:
      "Scan a Git repository for vulnerable dependencies, secrets, Infrastructure as Code misconfigurations and licenses.",
    providerTypes: ["iac"] as const,
  },
  {
    value: TRIVY_MODE.IAC,
    label: "Infrastructure as Code (repository policies)",
    description:
      "Check the Terraform, CloudFormation and Kubernetes files in a repository source against cloud security policies.",
    providerTypes: ["iac"] as const,
  },
  {
    value: TRIVY_MODE.IMAGE,
    label: "Container image",
    description: "Scan container images from a container registry source.",
    providerTypes: ["image"] as const,
  },
  {
    value: TRIVY_MODE.FS,
    label: "Code archive",
    description:
      "Scan an uploaded zip or tar archive for vulnerable dependencies, misconfigurations, secrets and licenses.",
    providerTypes: ["iac"] as const,
  },
  {
    value: TRIVY_MODE.SBOM,
    label: "SBOM",
    description:
      "Check the components listed in an SBOM document for known vulnerabilities.",
    providerTypes: ["iac"] as const,
  },
  {
    value: TRIVY_MODE.K8S,
    label: "Kubernetes",
    description:
      "Scan a Kubernetes cluster from a connected Kubernetes source.",
    providerTypes: ["kubernetes"] as const,
  },
  {
    value: TRIVY_MODE.SAST,
    label: "Static analysis (SAST)",
    description:
      "Analyze source code for security bugs such as injection, XSS and insecure crypto",
    providerTypes: ["iac"] as const,
  },
] as const;

export const TRIVY_SCANNER_OPTIONS = [
  {
    value: TRIVY_SCANNER.VULN,
    label: "Vulnerabilities",
    description: "Known CVEs in dependencies and OS packages.",
  },
  {
    value: TRIVY_SCANNER.MISCONFIG,
    label: "Misconfigurations (IaC)",
    description: "Terraform, CloudFormation, Kubernetes and Dockerfile issues.",
  },
  {
    value: TRIVY_SCANNER.SECRET,
    label: "Secrets",
    description: "Keys, tokens and passwords committed to code.",
  },
  {
    value: TRIVY_SCANNER.LICENSE,
    label: "Licenses",
    description: "Restricted or unknown open-source licenses.",
  },
  {
    value: TRIVY_SCANNER.RBAC,
    label: "RBAC",
    description: "Over-privileged Kubernetes roles and bindings.",
  },
] as const;

const { VULN, MISCONFIG, SECRET, LICENSE, RBAC } = TRIVY_SCANNER;

// Mirrors `MODE_SCANNERS` / `MODE_DEFAULT_SCANNERS` (`services/trivy.py`).
const MODE_SCANNERS: Partial<Record<TrivyMode, readonly TrivyScanner[]>> = {
  [TRIVY_MODE.IAC]: [VULN, MISCONFIG, SECRET],
  [TRIVY_MODE.IMAGE]: [VULN, MISCONFIG, SECRET],
  [TRIVY_MODE.FS]: [VULN, MISCONFIG, SECRET, LICENSE],
  [TRIVY_MODE.REPO]: [VULN, MISCONFIG, SECRET, LICENSE],
  [TRIVY_MODE.SBOM]: [VULN, LICENSE],
  [TRIVY_MODE.K8S]: [VULN, MISCONFIG, SECRET, RBAC],
};

const MODE_DEFAULT_SCANNERS: Partial<
  Record<TrivyMode, readonly TrivyScanner[]>
> = {
  ...MODE_SCANNERS,
  [TRIVY_MODE.SBOM]: [VULN],
  [TRIVY_MODE.K8S]: [VULN, MISCONFIG, SECRET],
};

/** Modes whose provider scan runs every listed scanner regardless of choice. */
const FIXED_SCANNER_MODES: readonly TrivyMode[] = [
  TRIVY_MODE.IAC,
  TRIVY_MODE.IMAGE,
];

/** Scanners a mode supports; empty for static analysis. */
export const scannersForMode = (mode: TrivyMode): readonly TrivyScanner[] =>
  MODE_SCANNERS[mode] ?? [];

export const defaultScannersForMode = (mode: TrivyMode): TrivyScanner[] => [
  ...(MODE_DEFAULT_SCANNERS[mode] ?? []),
];

export const hasFixedScanners = (mode: TrivyMode): boolean =>
  FIXED_SCANNER_MODES.includes(mode);

/** Supported scanners from `values`, in canonical order, or the mode default. */
export const scannersForModeFrom = (
  mode: TrivyMode,
  values: readonly string[],
): TrivyScanner[] => {
  const supported = scannersForMode(mode).filter((name) =>
    values.includes(name),
  );
  return supported.length > 0 ? supported : defaultScannersForMode(mode);
};

export const labelForTrivyScanner = (scanner: string): string =>
  TRIVY_SCANNER_OPTIONS.find((item) => item.value === scanner)?.label ??
  scanner;

const PROVIDER_TYPE_LABELS: Record<string, string> = {
  iac: "Code repository",
  image: "Container registry",
  kubernetes: "Kubernetes",
};

export const labelForProviderType = (providerType: string): string =>
  PROVIDER_TYPE_LABELS[providerType] ?? providerType;

export const SAST_RULESET_OPTIONS = [
  {
    value: SAST_RULESET.AUTO,
    label: "Detect languages",
    description: "Pick rules for the languages found in the code.",
  },
  {
    value: SAST_RULESET.ALL,
    label: "All languages",
    description: "Run every supported rule pack.",
  },
  { value: SAST_RULESET.CSHARP, label: "C#", description: "" },
  { value: SAST_RULESET.GO, label: "Go", description: "" },
  { value: SAST_RULESET.JAVA, label: "Java", description: "" },
  {
    value: SAST_RULESET.JAVASCRIPT,
    label: "JavaScript / TypeScript",
    description: "",
  },
  { value: SAST_RULESET.PYTHON, label: "Python", description: "" },
  { value: SAST_RULESET.SCALA, label: "Scala", description: "" },
] as const;

export const labelForTrivyMode = (mode: string): string =>
  TRIVY_MODE_OPTIONS.find((item) => item.value === mode)?.label ?? mode;

export const providerTypesForMode = (mode: TrivyMode): readonly string[] => {
  const option = TRIVY_MODE_OPTIONS.find((item) => item.value === mode);
  return option?.providerTypes ?? [];
};

export const findingsHrefForScan = (scanId: string): string =>
  `/findings?filter[scan__in]=${encodeURIComponent(scanId)}`;
