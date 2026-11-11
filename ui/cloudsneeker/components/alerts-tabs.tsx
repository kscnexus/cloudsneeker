import Link from "next/link";

import {
  ALERTS_HISTORY_TAB,
  ALERTS_TAB_PARAM,
} from "@/cloudsneeker/lib/alert-history";
import { cn } from "@/lib/utils";

export const ALERTS_VIEW = {
  RULES: "rules",
  HISTORY: "history",
} as const;

export type AlertsView = (typeof ALERTS_VIEW)[keyof typeof ALERTS_VIEW];

interface AlertsTabsProps {
  active: AlertsView;
}

const TAB_CLASS = "border-b-2 px-1 pb-2 text-sm font-medium transition-colors";

/** Rules and History views of the Alerts page. */
export const AlertsTabs = ({ active }: AlertsTabsProps) => (
  <nav aria-label="Alerts views" className="mb-4 flex gap-6">
    <Link
      href="/alerts"
      aria-current={active === ALERTS_VIEW.RULES ? "page" : undefined}
      className={cn(
        TAB_CLASS,
        active === ALERTS_VIEW.RULES
          ? "border-button-primary text-text-neutral-primary"
          : "text-text-neutral-secondary border-transparent",
      )}
    >
      Rules
    </Link>
    <Link
      href={`/alerts?${ALERTS_TAB_PARAM}=${ALERTS_HISTORY_TAB}`}
      aria-current={active === ALERTS_VIEW.HISTORY ? "page" : undefined}
      className={cn(
        TAB_CLASS,
        active === ALERTS_VIEW.HISTORY
          ? "border-button-primary text-text-neutral-primary"
          : "text-text-neutral-secondary border-transparent",
      )}
    >
      History
    </Link>
  </nav>
);
