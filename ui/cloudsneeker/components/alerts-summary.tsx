import { BellOff, BellRing, Send, ShieldCheck } from "lucide-react";

import {
  type AlertRuleSummaryInput,
  summarizeAlerts,
} from "@/cloudsneeker/lib/ops-summary";

import { STAT_TILE_TONE, StatTile } from "./stat-tile";

interface AlertsSummaryProps {
  alerts: AlertRuleSummaryInput[];
  /** Total rules across every page, from the API pagination. */
  totalCount?: number;
  /** The list failed to load; the page shows its own error. */
  unavailable?: boolean;
}

/** Key figures above the Alerts table, matching the product hub pages. */
export const AlertsSummary = ({
  alerts,
  totalCount,
  unavailable = false,
}: AlertsSummaryProps) => {
  if (unavailable) return null;

  const summary = summarizeAlerts(alerts, totalCount);
  const pageHint =
    summary.loaded < summary.total ? "Rules on this page" : undefined;

  return (
    <ul
      aria-label="Alert figures"
      data-slot="alerts-summary"
      className="mb-6 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4"
    >
      <li className="min-w-0">
        <StatTile
          label="Alert rules"
          value={summary.total}
          hint="Created from Findings filters"
          tone={STAT_TILE_TONE.ACCENT}
          icon={<BellRing />}
        />
      </li>
      <li className="min-w-0">
        <StatTile
          label="Active"
          value={summary.active}
          hint={pageHint ?? "Evaluated after scans"}
          tone={STAT_TILE_TONE.SUCCESS}
          icon={<ShieldCheck />}
        />
      </li>
      <li className="min-w-0">
        <StatTile
          label="Paused"
          value={summary.paused}
          hint={pageHint ?? "Not evaluated until enabled"}
          tone={
            summary.paused > 0 ? STAT_TILE_TONE.WARNING : STAT_TILE_TONE.NEUTRAL
          }
          icon={<BellOff />}
        />
      </li>
      <li className="min-w-0">
        <StatTile
          label="Destinations"
          value={summary.destinations}
          hint={pageHint ?? "Email recipients and Slack channels"}
          tone={STAT_TILE_TONE.INFO}
          icon={<Send />}
        />
      </li>
    </ul>
  );
};
