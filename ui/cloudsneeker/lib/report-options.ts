// Filter options for the report forms: sources come from the providers API
// and frameworks from the compliance overviews of recent completed scans
// (the same source the compliance page reads).

import {
  frameworkLabel,
  withoutEngineName,
} from "@/cloudsneeker/lib/report-view";

const PROVIDER_SUFFIX: Record<string, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "GCP",
  kubernetes: "Kubernetes",
  m365: "M365",
  github: "GitHub",
  oraclecloud: "Oracle Cloud",
  alibabacloud: "Alibaba Cloud",
  mongodbatlas: "MongoDB Atlas",
  nhn: "NHN",
};

export interface ReportSelectOption {
  id: string;
  label: string;
}

interface ProviderLike {
  id: string;
  attributes: { provider?: string; alias?: string | null; uid?: string };
}

interface OverviewLike {
  id: string;
  attributes?: { framework?: string; version?: string };
}

interface ScanLike {
  id: string;
  relationships?: { provider?: { data?: { id?: string } | null } };
}

export const providerOptions = (
  providers: ProviderLike[],
): ReportSelectOption[] =>
  providers.map((provider) => ({
    id: provider.id,
    label: [
      provider.attributes.provider,
      provider.attributes.alias || provider.attributes.uid || provider.id,
    ]
      .filter(Boolean)
      .join(" · "),
  }));

/** Latest completed scan id per provider, newest first, capped. */
export const latestScanPerProvider = (
  scans: ScanLike[],
  limit: number,
): string[] => {
  const seen = new Set<string>();
  const ids: string[] = [];
  for (const scan of scans) {
    const providerId = scan.relationships?.provider?.data?.id ?? scan.id;
    if (seen.has(providerId)) continue;
    seen.add(providerId);
    ids.push(scan.id);
    if (ids.length >= limit) break;
  }
  return ids;
};

/** Unique frameworks across overview lists, sorted by label. */
export const frameworkOptions = (
  overviews: OverviewLike[][],
): ReportSelectOption[] => {
  const byId = new Map<string, ReportSelectOption>();
  for (const list of overviews) {
    for (const overview of list) {
      if (!overview.id || byId.has(overview.id)) continue;
      const framework = overview.attributes?.framework;
      const version = overview.attributes?.version;
      const provider = overview.id.split("_").pop() ?? "";
      const base = framework
        ? [framework, version].filter(Boolean).join(" ")
        : frameworkLabel(overview.id);
      const suffix = PROVIDER_SUFFIX[provider.toLowerCase()];
      byId.set(overview.id, {
        id: overview.id,
        label: withoutEngineName(
          suffix && !base.includes(suffix) ? `${base} · ${suffix}` : base,
        ),
      });
    }
  }
  return Array.from(byId.values()).sort((a, b) =>
    a.label.localeCompare(b.label),
  );
};
