// Counts for the summary tiles above the Alerts and Scan profiles pages.
// Inputs are structural so the upstream resource types satisfy them without
// this module importing upstream page code.

export interface AlertRuleSummaryInput {
  attributes: {
    enabled: boolean;
    recipient_emails?: string[];
    slack_channels?: { id: string }[];
  };
}

export interface AlertsSummary {
  /** Rules across every page (API count), or the loaded rows. */
  total: number;
  /** Rules loaded on this page; the other counts cover only these. */
  loaded: number;
  active: number;
  paused: number;
  /** Distinct email recipients and Slack channels on the loaded rules. */
  destinations: number;
}

export const summarizeAlerts = (
  alerts: AlertRuleSummaryInput[],
  totalCount?: number,
): AlertsSummary => {
  const emails = new Set<string>();
  const channels = new Set<string>();
  let active = 0;
  for (const alert of alerts) {
    if (alert.attributes.enabled) active += 1;
    for (const email of alert.attributes.recipient_emails ?? []) {
      const normalized = email.trim().toLowerCase();
      if (normalized) emails.add(normalized);
    }
    for (const channel of alert.attributes.slack_channels ?? []) {
      if (channel.id) channels.add(channel.id);
    }
  }
  const loaded = alerts.length;
  return {
    total: Math.max(totalCount ?? loaded, loaded),
    loaded,
    active,
    paused: loaded - active,
    destinations: emails.size + channels.size,
  };
};

export interface ScanProfileSummaryInput {
  attributes: {
    providers: string[];
    updated_at: string;
  };
}

export interface ScanProfilesSummary {
  profiles: number;
  /** Providers with at least one profile attached. */
  coveredProviders: number;
  /** Providers still scanned with the built-in defaults. */
  defaultProviders: number;
  /** ISO timestamp of the most recent edit, or null. */
  lastUpdated: string | null;
}

export const summarizeScanProfiles = (
  profiles: ScanProfileSummaryInput[],
  providerIds: string[],
): ScanProfilesSummary => {
  const known = new Set(providerIds);
  const covered = new Set<string>();
  let lastUpdated: string | null = null;
  let lastTime = Number.NEGATIVE_INFINITY;
  for (const profile of profiles) {
    for (const providerId of profile.attributes.providers) {
      if (known.has(providerId)) covered.add(providerId);
    }
    const time = Date.parse(profile.attributes.updated_at);
    if (!Number.isNaN(time) && time > lastTime) {
      lastTime = time;
      lastUpdated = profile.attributes.updated_at;
    }
  }
  return {
    profiles: profiles.length,
    coveredProviders: covered.size,
    defaultProviders: known.size - covered.size,
    lastUpdated,
  };
};
