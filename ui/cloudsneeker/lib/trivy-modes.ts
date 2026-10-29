import { TRIVY_MODE, type TrivyMode } from "@/cloudsneeker/types/trivy";

export const TRIVY_MODE_OPTIONS = [
  {
    value: TRIVY_MODE.IAC,
    label: "Infrastructure as Code",
    description:
      "Scan Terraform, CloudFormation and Kubernetes manifests from an Infrastructure as Code source.",
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
      "Scan an uploaded zip or tar archive for vulnerable dependencies, misconfigurations and secrets.",
    providerTypes: ["iac"] as const,
  },
  {
    value: TRIVY_MODE.REPO,
    label: "Dependencies (repository)",
    description:
      "Scan a remote Git repository for vulnerable dependencies and secrets. Attach it to an Infrastructure as Code source.",
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
    description: "Scan a Kubernetes cluster from a connected Kubernetes source.",
    providerTypes: ["kubernetes"] as const,
  },
] as const;

export const labelForTrivyMode = (mode: string): string =>
  TRIVY_MODE_OPTIONS.find((item) => item.value === mode)?.label ?? mode;

export const providerTypesForMode = (mode: TrivyMode): readonly string[] => {
  const option = TRIVY_MODE_OPTIONS.find((item) => item.value === mode);
  return option?.providerTypes ?? [];
};

export const findingsHrefForScan = (scanId: string): string =>
  `/findings?filter[scan__in]=${encodeURIComponent(scanId)}`;
