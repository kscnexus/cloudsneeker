// Sidebar entries for Cloudsneeker-only pages under `app/(cloudsneeker)/`.
// Upstream `navigation-config.ts` calls `withCloudsneekerNavigation` through
// one `cloudsneeker-hook` line; add new pages here, not there.

import { Info } from "lucide-react";

import {
  NAVIGATION_ITEM_KIND,
  type NavigationItem,
  type NavigationSection,
} from "@/components/layout/app-sidebar/types";

import { BRAND } from "./brand";

export const CLOUDSNEEKER_ROUTE = {
  ABOUT: "/about",
} as const;

export type CloudsneekerRoute =
  (typeof CLOUDSNEEKER_ROUTE)[keyof typeof CLOUDSNEEKER_ROUTE];

const HELP_SECTION_LABEL = "HELP";

const isRouteActive = (pathname: string, href: string): boolean =>
  pathname === href || pathname.startsWith(`${href}/`);

export const getCloudsneekerNavigationItems = (
  pathname: string,
): NavigationItem[] => [
  {
    kind: NAVIGATION_ITEM_KIND.LINK,
    href: CLOUDSNEEKER_ROUTE.ABOUT,
    label: `About ${BRAND.name}`,
    icon: Info,
    active: isRouteActive(pathname, CLOUDSNEEKER_ROUTE.ABOUT),
  },
];

export const withCloudsneekerNavigation = (
  sections: NavigationSection[],
  pathname: string,
): NavigationSection[] => {
  const items = getCloudsneekerNavigationItems(pathname);
  const hasHelpSection = sections.some(
    (section) => section.label === HELP_SECTION_LABEL,
  );

  if (!hasHelpSection) {
    return [...sections, { label: HELP_SECTION_LABEL, items }];
  }

  return sections.map((section) =>
    section.label === HELP_SECTION_LABEL
      ? { ...section, items: [...section.items, ...items] }
      : section,
  );
};
