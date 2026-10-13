// Sidebar entries for Cloudsneeker-only pages under `app/(cloudsneeker)/`.
// Upstream `navigation-config.ts` calls `withCloudsneekerNavigation` through
// one `cloudsneeker-hook` line; add new pages here, not there.

import {
  NAVIGATION_ITEM_KIND,
  type NavigationChild,
  type NavigationSection,
} from "@/components/layout/app-sidebar/types";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { isCloudsneekerFeatureEnabled } from "./features";

const HELP_SECTION_LABEL = "HELP";

const FEATURE_LINKS: Partial<
  Record<
    (typeof CLOUD_UPGRADE_FEATURE)[keyof typeof CLOUD_UPGRADE_FEATURE],
    { href: string; label: string } | null
  >
> = {
  [CLOUD_UPGRADE_FEATURE.ALERTS]: isCloudsneekerFeatureEnabled("alerts")
    ? { href: "/alerts", label: "Alerts" }
    : null,
  [CLOUD_UPGRADE_FEATURE.SCAN_CONFIGURATION]: isCloudsneekerFeatureEnabled(
    "scanConfiguration",
  )
    ? { href: "/scans/config", label: "Scan profiles" }
    : null,
  [CLOUD_UPGRADE_FEATURE.CLI_IMPORT]: isCloudsneekerFeatureEnabled("cliImport")
    ? { href: "/scans?import=1", label: "CLI Import" }
    : null,
};

const toCloudsneekerChild = (
  child: NavigationChild,
  pathname: string,
): NavigationChild | null => {
  if (child.kind !== NAVIGATION_ITEM_KIND.CLOUD_UPGRADE) return child;

  const link = FEATURE_LINKS[child.cloudUpgradeFeature];
  if (!link) return null;

  return {
    kind: NAVIGATION_ITEM_KIND.LINK,
    href: link.href,
    label: link.label,
    active:
      pathname === link.href.split("?")[0] ||
      pathname.startsWith(`${link.href.split("?")[0]}/`),
    highlight: true,
  };
};

export const withCloudsneekerNavigation = (
  sections: NavigationSection[],
  pathname: string,
): NavigationSection[] =>
  sections
    .filter((section) => section.label !== HELP_SECTION_LABEL)
    .map((section) => {
      let changed = false;
      const items = section.items.map((item) => {
        if (item.kind !== NAVIGATION_ITEM_KIND.COLLAPSIBLE) return item;

        const children = item.children
          .map((child) => toCloudsneekerChild(child, pathname))
          .filter((child): child is NavigationChild => child !== null);

        if (
          children.length === item.children.length &&
          children.every((child, index) => child === item.children[index])
        ) {
          return item;
        }

        changed = true;
        return { ...item, children };
      });

      return changed ? { ...section, items } : section;
    });
