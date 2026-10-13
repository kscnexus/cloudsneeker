// Sidebar entries for Cloudsneeker-only pages under `app/(cloudsneeker)/`.
// Upstream `navigation-config.ts` calls `withCloudsneekerNavigation` through
// one `cloudsneeker-hook` line; add new pages here, not there.

import {
  NAVIGATION_ITEM_KIND,
  type NavigationSection,
} from "@/components/layout/app-sidebar/types";

const HELP_SECTION_LABEL = "HELP";

export const withCloudsneekerNavigation = (
  sections: NavigationSection[],
  _pathname: string,
): NavigationSection[] =>
  sections
    .filter((section) => section.label !== HELP_SECTION_LABEL)
    .map((section) => {
      let changed = false;
      const items = section.items.map((item) => {
        if (item.kind !== NAVIGATION_ITEM_KIND.COLLAPSIBLE) return item;

        const children = item.children.filter(
          (child) => child.kind !== NAVIGATION_ITEM_KIND.CLOUD_UPGRADE,
        );
        if (children.length === item.children.length) return item;

        changed = true;
        return { ...item, children };
      });

      return changed ? { ...section, items } : section;
    });
