import {
  CalendarClock,
  Layers,
  ServerCog,
  SlidersVertical,
} from "lucide-react";

import {
  type ScanProfileSummaryInput,
  summarizeScanProfiles,
} from "@/cloudsneeker/lib/ops-summary";
import { CLOUDSNEEKER_SURFACE } from "@/cloudsneeker/lib/ui-classes";

import { STAT_TILE_TONE, StatTile } from "./stat-tile";

const DATE_FORMAT = new Intl.DateTimeFormat("en-US", {
  dateStyle: "medium",
  timeZone: "UTC",
});

export const formatProfileDate = (value: string | null): string => {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : DATE_FORMAT.format(date);
};

interface ScanProfilesSummaryProps {
  profiles: ScanProfileSummaryInput[];
  /** Ids of the providers loaded for the page. */
  providerIds: string[];
}

/** Key figures above the Scan profiles table. */
export const ScanProfilesSummary = ({
  profiles,
  providerIds,
}: ScanProfilesSummaryProps) => {
  const summary = summarizeScanProfiles(profiles, providerIds);

  return (
    <ul
      aria-label="Scan profile figures"
      data-slot="scan-profiles-summary"
      data-cloudsneeker-surface={CLOUDSNEEKER_SURFACE.SCAN_PROFILES}
      className="mb-6 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4"
    >
      <li className="min-w-0">
        <StatTile
          label="Scan profiles"
          value={summary.profiles}
          hint="Check settings applied at scan time"
          tone={STAT_TILE_TONE.ACCENT}
          icon={<SlidersVertical />}
        />
      </li>
      <li className="min-w-0">
        <StatTile
          label="Providers with a profile"
          value={summary.coveredProviders}
          hint={`Of ${providerIds.length} connected`}
          tone={STAT_TILE_TONE.SUCCESS}
          icon={<Layers />}
        />
      </li>
      <li className="min-w-0">
        <StatTile
          label="Using defaults"
          value={summary.defaultProviders}
          hint="Scanned with the built-in settings"
          tone={STAT_TILE_TONE.NEUTRAL}
          icon={<ServerCog />}
        />
      </li>
      <li className="min-w-0">
        <StatTile
          label="Last edited"
          value={formatProfileDate(summary.lastUpdated)}
          hint="Most recent profile change"
          tone={STAT_TILE_TONE.INFO}
          icon={<CalendarClock />}
        />
      </li>
    </ul>
  );
};
