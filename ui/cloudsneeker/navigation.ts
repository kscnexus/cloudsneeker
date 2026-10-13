// Sidebar entries for Cloudsneeker-only pages under `app/(cloudsneeker)/`.
// Upstream `navigation-config.ts` calls `withCloudsneekerNavigation` through
// one `cloudsneeker-hook` line; add new pages here, not there.

import type { NavigationSection } from "@/components/layout/app-sidebar/types";

const HELP_SECTION_LABEL = "HELP";

export const withCloudsneekerNavigation = (
  sections: NavigationSection[],
  _pathname: string,
): NavigationSection[] =>
  sections.filter((section) => section.label !== HELP_SECTION_LABEL);
