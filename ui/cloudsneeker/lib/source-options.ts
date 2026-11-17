import { labelForProviderType } from "@/cloudsneeker/lib/trivy-modes";

/** One connected source (a provider) in a picker. */
export interface SourceOption {
  id: string;
  label: string;
  providerType?: string;
}

/** A GitHub connection and the code repository sources imported from it. */
export interface SourceConnectionOption {
  id: string;
  label: string;
  repositoryIds: string[];
}

export interface SourceGroup {
  label: string;
  options: SourceOption[];
}

interface ProviderLike {
  id: string;
  attributes: {
    provider?: string;
    alias?: string | null;
    uid?: string | null;
  };
}

/** Picker option of a provider: `<type> · <alias or uid>`. */
export const sourceOption = (provider: ProviderLike): SourceOption => ({
  id: provider.id,
  providerType: provider.attributes.provider,
  label: [
    labelForProviderType(provider.attributes.provider ?? ""),
    provider.attributes.alias || provider.attributes.uid || provider.id,
  ]
    .filter(Boolean)
    .join(" · "),
});

/** The label without its `<type> · ` prefix (inside a group of that type). */
const shortLabel = (option: SourceOption): string => {
  const prefix = `${labelForProviderType(option.providerType ?? "")} · `;
  return option.label.startsWith(prefix)
    ? option.label.slice(prefix.length)
    : option.label;
};

const byLabel = (a: SourceOption, b: SourceOption) =>
  a.label.localeCompare(b.label);

/**
 * Sources grouped the same way in every picker: code repositories under the
 * GitHub connection they were imported from, then other code repositories,
 * then one group per provider type.
 */
export const groupSourceOptions = (
  options: SourceOption[],
  connections: SourceConnectionOption[] = [],
): SourceGroup[] => {
  const byId = new Map(options.map((option) => [option.id, option]));
  const placed = new Set<string>();
  const groups: SourceGroup[] = [];

  for (const connection of connections) {
    const members = connection.repositoryIds
      .map((repositoryId) => byId.get(repositoryId))
      .filter((option): option is SourceOption => Boolean(option))
      .map((option) => ({ ...option, label: shortLabel(option) }))
      .sort(byLabel);
    if (members.length === 0) continue;
    members.forEach((option) => placed.add(option.id));
    groups.push({ label: `GitHub · ${connection.label}`, options: members });
  }

  const byType = new Map<string, SourceOption[]>();
  for (const option of options) {
    if (placed.has(option.id)) continue;
    const type = option.providerType ?? "";
    byType.set(type, [...(byType.get(type) ?? []), option]);
  }
  const types = Array.from(byType.keys()).sort((a, b) =>
    labelForProviderType(a).localeCompare(labelForProviderType(b)),
  );
  for (const type of types) {
    const members = (byType.get(type) ?? [])
      .map((option) => ({ ...option, label: shortLabel(option) }))
      .sort(byLabel);
    const typeLabel = labelForProviderType(type) || "Other";
    groups.push({
      label:
        type === "iac" && groups.length > 0
          ? `Other ${typeLabel.toLowerCase()} sources`
          : typeLabel,
      options: members,
    });
  }
  return groups;
};
