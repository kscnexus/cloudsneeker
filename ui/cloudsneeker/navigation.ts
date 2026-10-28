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

const PROFILE_CHILD: NavigationChild = {
  kind: NAVIGATION_ITEM_KIND.LINK,
  href: "/profile",
  label: "Profile",
};

const CUSTODIAN_CHILD: NavigationChild = {
  kind: NAVIGATION_ITEM_KIND.LINK,
  href: "/custodian",
  label: "Cloud Custodian",
};

const TRIVY_CHILD: NavigationChild = {
  kind: NAVIGATION_ITEM_KIND.LINK,
  href: "/trivy",
  label: "Trivy",
};

const withInjectedChild = (
  children: NavigationChild[],
  child: NavigationChild,
  pathname: string,
): NavigationChild[] => {
  if (child.kind !== NAVIGATION_ITEM_KIND.LINK) {
    return children;
  }

  const active =
    pathname === child.href || pathname.startsWith(`${child.href}/`);

  if (children.some((existing) => existing.label === child.label)) {
    return children.map((existing) =>
      existing.label === child.label &&
      existing.kind === NAVIGATION_ITEM_KIND.LINK
        ? { ...existing, active }
        : existing,
    );
  }

  return [{ ...child, active }, ...children];
};

const withProfileChild = (
  children: NavigationChild[],
  pathname: string,
): NavigationChild[] => withInjectedChild(children, PROFILE_CHILD, pathname);

const withCustodianChild = (
  children: NavigationChild[],
  pathname: string,
): NavigationChild[] => {
  if (!isCloudsneekerFeatureEnabled("custodian")) {
    return children;
  }
  return withInjectedChild(children, CUSTODIAN_CHILD, pathname);
};

const withTrivyChild = (
  children: NavigationChild[],
  pathname: string,
): NavigationChild[] => {
  if (!isCloudsneekerFeatureEnabled("trivy")) {
    return children;
  }
  return withInjectedChild(children, TRIVY_CHILD, pathname);
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

        let children = item.children
          .map((child) => toCloudsneekerChild(child, pathname))
          .filter((child): child is NavigationChild => child !== null);

        // Profile lives under Organization so the page is reachable from the sidebar.
        if (item.label === "Organization") {
          const nextChildren = withProfileChild(children, pathname);
          if (nextChildren !== children) {
            children = nextChildren;
            changed = true;
          }
        }

        // Cloud Custodian and Trivy are Cloudsneeker-only Configuration tools.
        if (item.label === "Configuration") {
          let nextChildren = withCustodianChild(children, pathname);
          nextChildren = withTrivyChild(nextChildren, pathname);
          if (nextChildren !== children) {
            children = nextChildren;
            changed = true;
          }
        }

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
