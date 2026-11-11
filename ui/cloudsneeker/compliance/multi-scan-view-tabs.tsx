import Link from "next/link";

import { cn } from "@/lib/utils";

import {
  MULTI_SCAN_VIEW,
  type MultiScanView,
  multiScanViewHref,
} from "./accounts-view";

const TAB_CLASS = "rounded-md px-3 py-1.5 text-sm font-medium";

interface MultiScanViewTabsProps {
  active: MultiScanView;
  providerType?: string | null;
}

/** "Compare two scans" and "Across accounts" views of Multiple Scans. */
export const MultiScanViewTabs = ({
  active,
  providerType,
}: MultiScanViewTabsProps) => (
  <nav
    aria-label="Multiple Scans views"
    className="bg-bg-neutral-tertiary flex w-fit gap-1 rounded-lg p-1"
  >
    {[
      { view: MULTI_SCAN_VIEW.SCANS, label: "Compare two scans" },
      { view: MULTI_SCAN_VIEW.ACCOUNTS, label: "Across accounts" },
    ].map((tab) => (
      <Link
        key={tab.view}
        href={multiScanViewHref(tab.view, providerType)}
        aria-current={active === tab.view ? "page" : undefined}
        className={cn(
          TAB_CLASS,
          active === tab.view
            ? "bg-bg-neutral-primary text-text-neutral-primary shadow-sm"
            : "text-text-neutral-secondary",
        )}
      >
        {tab.label}
      </Link>
    ))}
  </nav>
);
