import { TRIVY_MODE, type TrivyMode } from "@/cloudsneeker/types/trivy";

export const TRIVY_MODE_OPTIONS = [
  {
    value: TRIVY_MODE.IAC,
    label: "IaC",
    description: "Scan Terraform / Kubernetes manifests via the IaC provider.",
    providerTypes: ["iac"] as const,
  },
  {
    value: TRIVY_MODE.IMAGE,
    label: "Container image",
    description: "Scan container images via the Image provider.",
    providerTypes: ["image"] as const,
  },
  {
    value: TRIVY_MODE.FS,
    label: "Filesystem",
    description: "Scan an uploaded archive with trivy fs.",
    providerTypes: ["iac"] as const,
  },
  {
    value: TRIVY_MODE.REPO,
    label: "Repository",
    description:
      "Scan a remote git repository with trivy repo. Attach it to an Infrastructure as Code provider.",
    providerTypes: ["iac"] as const,
  },
  {
    value: TRIVY_MODE.SBOM,
    label: "SBOM",
    description: "Scan an SBOM document with trivy sbom.",
    providerTypes: ["iac"] as const,
  },
  {
    value: TRIVY_MODE.K8S,
    label: "Kubernetes",
    description: "Scan a cluster with trivy k8s using a Kubernetes provider.",
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
