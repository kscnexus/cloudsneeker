import { SUBSCRIPTION_STATUS_LABEL } from "@/cloudsneeker/lib/entitlements";
import { statusTone } from "@/cloudsneeker/lib/operator";
import type { SubscriptionStatus } from "@/cloudsneeker/types/operator";
import { Badge } from "@/components/shadcn";

const BADGE_VARIANT = {
  success: "success",
  warning: "warning",
  danger: "error",
  info: "info",
} as const;

type BadgeTone = keyof typeof BADGE_VARIANT;

export const SubscriptionStatusBadge = ({
  status,
}: {
  status: SubscriptionStatus;
}) => {
  const tone = statusTone(status);
  const variant =
    tone in BADGE_VARIANT ? BADGE_VARIANT[tone as BadgeTone] : "outline";
  return (
    <Badge variant={variant} data-status={status}>
      {SUBSCRIPTION_STATUS_LABEL[status] ?? status}
    </Badge>
  );
};
