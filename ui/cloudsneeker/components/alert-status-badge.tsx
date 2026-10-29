import { Badge } from "@/components/shadcn/badge/badge";
import { cn } from "@/lib/utils";

/** Labels match the upstream Status column so sorting and tests still read them. */
export const ALERT_STATUS_LABEL = {
  ENABLED: "Enabled",
  DISABLED: "Disabled",
} as const;

export const alertStatusLabel = (enabled: boolean): string =>
  enabled ? ALERT_STATUS_LABEL.ENABLED : ALERT_STATUS_LABEL.DISABLED;

/** Status pill for an alert rule on the Alerts list. */
export const AlertStatusBadge = ({ enabled }: { enabled: boolean }) => (
  <Badge
    variant={enabled ? "success" : "tag"}
    data-slot="alert-status-badge"
    data-enabled={enabled ? "true" : "false"}
  >
    <span
      aria-hidden="true"
      className={cn(
        "size-1.5 rounded-full",
        enabled ? "bg-bg-pass" : "bg-text-neutral-tertiary",
      )}
    />
    {alertStatusLabel(enabled)}
  </Badge>
);
