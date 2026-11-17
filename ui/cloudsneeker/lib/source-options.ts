import { labelForProviderType } from "@/cloudsneeker/lib/trivy-modes";

/** One connected source (a provider) in a picker. */
export interface SourceOption {
  id: string;
  label: string;
  providerType?: string;
  /** Provider uid: the repository URL of a code repository source. */
  uid?: string;
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

const GITHUB = "github";

/** Type label; covers provider types the scan-type labels do not name. */
const typeLabel = (type: string): string =>
  type === GITHUB ? "GitHub" : labelForProviderType(type);

/** Picker option of a provider: `<type> · <alias or uid>`. */
export const sourceOption = (provider: ProviderLike): SourceOption => ({
  id: provider.id,
  providerType: provider.attributes.provider,
  uid: provider.attributes.uid ?? undefined,
  label: [
    typeLabel(provider.attributes.provider ?? ""),
    provider.attributes.alias || provider.attributes.uid || provider.id,
  ]
    .filter(Boolean)
    .join(" · "),
});

/**
 * Owner of an HTTPS `github.com` repository URL, lower-cased; null otherwise.
 * Same rule as the API's `github_connection.github_owner`: such a repository
 * reads the credentials of the GitHub connection added for that owner.
 */
export const githubOwner = (url: string | undefined): string | null => {
  if (!url) return null;
  try {
    const parsed = new URL(url.trim());
    if (parsed.protocol !== "https:") return null;
    if (parsed.hostname.toLowerCase() !== "github.com") return null;
    const owner = parsed.pathname.split("/").filter(Boolean)[0];
    return owner ? owner.toLowerCase() : null;
  } catch {
    return null;
  }
};

/** The label without its `<type> · ` prefix (inside a group of that type). */
const shortLabel = (option: SourceOption): string => {
  const prefix = `${typeLabel(option.providerType ?? "")} · `;
  return option.label.startsWith(prefix)
    ? option.label.slice(prefix.length)
    : option.label;
};

const byLabel = (a: SourceOption, b: SourceOption) =>
  a.label.localeCompare(b.label);

/**
 * Sources grouped the same way in every picker: code repositories under the
 * GitHub connection of their owner (when one is connected; `context` may
 * hold connections that are not themselves offered), then the other
 * code repositories, then one group per provider type.
 */
export const groupSourceOptions = (
  options: SourceOption[],
  /** Other sources that can name a group (GitHub connections not offered). */
  context: SourceOption[] = [],
): SourceGroup[] => {
  const connections = new Map<string, SourceOption>();
  for (const option of [...context, ...options]) {
    if (option.providerType === GITHUB && option.uid) {
      connections.set(option.uid.toLowerCase(), option);
    }
  }
  const placed = new Set<string>();
  const byOwner = new Map<string, SourceOption[]>();
  for (const option of options) {
    if (option.providerType !== "iac") continue;
    const owner = githubOwner(option.uid);
    if (!owner || !connections.has(owner)) continue;
    byOwner.set(owner, [...(byOwner.get(owner) ?? []), option]);
    placed.add(option.id);
  }

  const groups: SourceGroup[] = Array.from(byOwner.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([owner, members]) => ({
      label: `GitHub · ${shortLabel(connections.get(owner) as SourceOption)}`,
      options: members
        .map((option) => ({ ...option, label: shortLabel(option) }))
        .sort(byLabel),
    }));

  const byType = new Map<string, SourceOption[]>();
  for (const option of options) {
    if (placed.has(option.id)) continue;
    const type = option.providerType ?? "";
    byType.set(type, [...(byType.get(type) ?? []), option]);
  }
  const types = Array.from(byType.keys()).sort((a, b) =>
    typeLabel(a).localeCompare(typeLabel(b)),
  );
  for (const type of types) {
    const groupName = typeLabel(type) || "Other";
    groups.push({
      label:
        type === "iac" && byOwner.size > 0
          ? `Other ${groupName.toLowerCase()} sources`
          : groupName,
      options: (byType.get(type) ?? [])
        .map((option) => ({ ...option, label: shortLabel(option) }))
        .sort(byLabel),
    });
  }
  return groups;
};
