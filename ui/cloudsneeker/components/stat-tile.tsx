import Link from "next/link";
import type { ReactNode } from "react";

import { FOCUS_RING_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { Card } from "@/components/shadcn/card/card";
import { cn } from "@/lib/utils";

export const STAT_TILE_TONE = {
  NEUTRAL: "neutral",
  ACCENT: "accent",
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "info",
  SUCCESS: "success",
  WARNING: "warning",
  DANGER: "danger",
} as const;

export type StatTileTone = (typeof STAT_TILE_TONE)[keyof typeof STAT_TILE_TONE];

const TONE_ACCENT_CLASS: Record<StatTileTone, string> = {
  neutral: "bg-border-neutral-tertiary",
  accent: "bg-button-tertiary",
  critical: "bg-bg-data-critical",
  high: "bg-bg-data-high",
  medium: "bg-bg-data-medium",
  low: "bg-bg-data-low",
  info: "bg-bg-data-info",
  success: "bg-bg-pass",
  warning: "bg-bg-warning",
  danger: "bg-bg-fail",
};

interface StatTileProps {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  /** Makes the whole tile a link. */
  href?: string;
  tone?: StatTileTone;
  icon?: ReactNode;
  /** Marks the tile that is the active filter. */
  selected?: boolean;
  className?: string;
}

export const StatTile = ({
  label,
  value,
  hint,
  href,
  tone = STAT_TILE_TONE.NEUTRAL,
  icon,
  selected = false,
  className,
}: StatTileProps) => {
  const tile = (
    <Card
      variant="base"
      padding="none"
      data-slot="stat-tile"
      data-tone={tone}
      className={cn(
        "relative h-full gap-0 overflow-hidden shadow-sm",
        href && "hover:border-border-neutral-tertiary transition-colors",
        selected && "border-button-tertiary",
        className,
      )}
    >
      <span
        aria-hidden="true"
        className={cn("absolute inset-y-0 left-0 w-1", TONE_ACCENT_CLASS[tone])}
      />
      <div className="flex h-full flex-col gap-1 py-4 pr-4 pl-5">
        <div className="flex items-center justify-between gap-2">
          <span className="text-text-neutral-secondary text-xs font-medium tracking-wide uppercase">
            {label}
          </span>
          {icon ? (
            <span
              aria-hidden="true"
              className="text-text-neutral-tertiary [&_svg]:size-4"
            >
              {icon}
            </span>
          ) : null}
        </div>
        <span className="text-text-neutral-primary text-2xl font-semibold tabular-nums">
          {value}
        </span>
        {hint ? (
          <span className="text-text-neutral-tertiary text-xs">{hint}</span>
        ) : null}
      </div>
    </Card>
  );

  if (!href) return tile;

  return (
    <Link
      href={href}
      aria-current={selected ? "true" : undefined}
      className={cn("block h-full rounded-xl", FOCUS_RING_CLASS)}
    >
      {tile}
    </Link>
  );
};
