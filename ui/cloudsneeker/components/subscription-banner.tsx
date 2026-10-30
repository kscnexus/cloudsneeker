import { AlertTriangle, Clock } from "lucide-react";

import type { SubscriptionBannerContent } from "@/cloudsneeker/lib/entitlements";
import { SUBSCRIPTION_BANNER_TONE } from "@/cloudsneeker/lib/entitlements";
import { cn } from "@/lib/utils";

interface SubscriptionBannerProps {
  banner: SubscriptionBannerContent;
  className?: string;
}

/**
 * Notice for a read-only subscription or a plan ending soon. Fixed to the
 * bottom of the window so it never shifts the inherited page layout.
 */
export const SubscriptionBanner = ({
  banner,
  className,
}: SubscriptionBannerProps) => {
  const danger = banner.tone === SUBSCRIPTION_BANNER_TONE.DANGER;
  const Icon = danger ? AlertTriangle : Clock;
  return (
    <div
      role={danger ? "alert" : "status"}
      data-slot="subscription-banner"
      data-tone={banner.tone}
      className={cn(
        "fixed right-4 bottom-4 left-4 z-50 flex items-start gap-3 rounded-xl border px-4 py-3 text-sm shadow-lg sm:left-auto sm:max-w-md",
        danger
          ? "border-border-error bg-bg-fail-secondary text-text-error-primary"
          : "border-border-neutral-secondary bg-bg-neutral-secondary text-text-neutral-primary",
        className,
      )}
    >
      <Icon aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
      <div className="flex min-w-0 flex-col gap-0.5">
        <p className="font-semibold">{banner.title}</p>
        <p className={danger ? undefined : "text-text-neutral-secondary"}>
          {banner.message}
        </p>
      </div>
    </div>
  );
};
