// Product sidebar. Upstream `navigation-config.ts` builds its own sections and
// passes them here through one `cloudsneeker-hook` line; this pass regroups
// them into the product areas (Cloud Security, Application Security, Cloud
// Governance, Reports, Operations, Settings). Upstream item objects are reused by href
// so permissions, active state and highlight keep working. Add new pages here,
// not in the upstream file.

import {
  Bell,
  Boxes,
  ClipboardCheck,
  FileBarChart,
  ListChecks,
  type LucideIcon,
  Package,
  Scale,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Upload,
} from "lucide-react";

import {
  NAVIGATION_ITEM_KIND,
  type NavigationChild,
  type NavigationChildLink,
  type NavigationCollapsible,
  type NavigationItem,
  type NavigationLink,
  type NavigationSection,
} from "@/components/layout/app-sidebar/types";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { BRAND } from "./brand";
import { isCloudsneekerFeatureEnabled } from "./features";
import {
  APPSEC_RESERVED_SEGMENTS,
  APPSEC_SEGMENT,
  APPSEC_WORKSPACES,
} from "./lib/appsec";
import { isHrefInPlan } from "./lib/entitlements";
import {
  AREA_PAGE_SEGMENT,
  appSecurityHref,
  governanceHref,
  PRODUCT_ROUTE,
} from "./routes";

export const NAVIGATION_SECTION_LABEL = {
  CLOUD_SECURITY: BRAND.cloudSecurityName.toUpperCase(),
  APPLICATION_SECURITY: BRAND.appSecurityName.toUpperCase(),
  GOVERNANCE: "GOVERNANCE",
  REPORTS: "REPORTS",
  OPERATIONS: "OPERATIONS",
  SETTINGS: "SETTINGS",
} as const;

const UPSTREAM_SECTION_LABEL = {
  SECURITY: "SECURITY",
  SETTINGS: "SETTINGS",
  HELP: "HELP",
} as const;

const UPSTREAM_COLLAPSIBLE_LABEL = {
  CONFIGURATION: "Configuration",
  ORGANIZATION: "Organization",
} as const;

const SETTINGS_CHILD_LABEL = {
  SOURCES: "Sources & Providers",
  ASSISTANT_SETTINGS: `${BRAND.assistantName} settings`,
} as const;

const OPERATIONS_LINKS = [
  { href: "/alerts", label: "Alerts", icon: Bell },
  { href: "/scans/config", label: "Scan profiles", icon: SlidersHorizontal },
  { href: "/scans?import=1", label: "CLI Import", icon: Upload },
] as const satisfies readonly {
  href: string;
  label: string;
  icon: LucideIcon;
}[];

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

const hrefPath = (href: string): string => href.split("?")[0] ?? href;

const isRouteActive = (pathname: string, href: string): boolean => {
  // Links that only differ by query (CLI Import) never steal the active state
  // from the page they open on.
  if (href.includes("?")) return false;
  const path = hrefPath(href);
  return pathname === path || pathname.startsWith(`${path}/`);
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
    active: isRouteActive(pathname, link.href),
    highlight: true,
  };
};

const PROFILE_CHILD: NavigationChildLink = {
  kind: NAVIGATION_ITEM_KIND.LINK,
  href: "/profile",
  label: "Profile",
};

/** MFA for the signed-in user; admins also set the tenant requirement. */
const SECURITY_CHILD: NavigationChildLink = {
  kind: NAVIGATION_ITEM_KIND.LINK,
  href: PRODUCT_ROUTE.SECURITY,
  label: "Security",
};

/** Tenant audit log; the page itself checks the manage account permission. */
const AUDIT_LOG_CHILD: NavigationChildLink = {
  kind: NAVIGATION_ITEM_KIND.LINK,
  href: PRODUCT_ROUTE.AUDIT_LOG,
  label: "Audit log",
};

/** Detection content and engine versions; any signed-in user. */
const CONTENT_VERSIONS_CHILD: NavigationChildLink = {
  kind: NAVIGATION_ITEM_KIND.LINK,
  href: PRODUCT_ROUTE.CONTENT_VERSIONS,
  label: "Content versions",
};

/** What each detection content release added, changed or removed. */
const RELEASE_NOTES_CHILD: NavigationChildLink = {
  kind: NAVIGATION_ITEM_KIND.LINK,
  href: PRODUCT_ROUTE.RELEASE_NOTES,
  label: "Release notes",
};

/** Operator console; only shown to platform operators (`/operator/me`). */
const OPERATOR_CONSOLE_CHILD: NavigationChildLink = {
  kind: NAVIGATION_ITEM_KIND.LINK,
  href: PRODUCT_ROUTE.OPERATOR_CONSOLE,
  label: "Operator console",
};

/** Plan features (`null` = unknown, show all) and operator access. */
export interface NavigationPlanState {
  features: readonly string[] | null;
  isOperator: boolean;
}

/** Before the plan loads: nothing hidden, no operator link. */
export const UNKNOWN_PLAN: NavigationPlanState = {
  features: null,
  isOperator: false,
};

interface UpstreamIndex {
  /** Top-level items with the label of the section they came from. */
  items: { item: NavigationItem; sectionLabel?: string }[];
  configuration?: NavigationCollapsible;
  organization?: NavigationCollapsible;
  /** Configuration children after cloud-feature conversion. */
  configurationChildren: NavigationChild[];
}

const indexUpstream = (
  sections: NavigationSection[],
  pathname: string,
): UpstreamIndex => {
  const index: UpstreamIndex = { items: [], configurationChildren: [] };

  for (const section of sections) {
    if (section.label === UPSTREAM_SECTION_LABEL.HELP) continue;
    for (const item of section.items) {
      if (item.kind === NAVIGATION_ITEM_KIND.COLLAPSIBLE) {
        if (item.label === UPSTREAM_COLLAPSIBLE_LABEL.CONFIGURATION) {
          index.configuration = item;
          index.configurationChildren = item.children
            .map((child) => toCloudsneekerChild(child, pathname))
            .filter((child): child is NavigationChild => child !== null);
          continue;
        }
        if (item.label === UPSTREAM_COLLAPSIBLE_LABEL.ORGANIZATION) {
          index.organization = item;
          continue;
        }
      }
      index.items.push({ item, sectionLabel: section.label });
    }
  }

  return index;
};

const productLink = (
  href: string,
  label: string,
  icon: LucideIcon,
  pathname: string,
): NavigationLink => ({
  kind: NAVIGATION_ITEM_KIND.LINK,
  href,
  label,
  icon,
  active: isRouteActive(pathname, href),
});

/**
 * Area hub link plus its Findings and Triage pages. The hub stays active on
 * its target and policy pages but not on the area findings or triage page.
 */
const areaLinks = (
  hubHref: string,
  hubLabel: string,
  hubIcon: LucideIcon,
  hrefFor: (segment: string) => string,
  pathname: string,
): NavigationLink[] => {
  const findings = productLink(
    hrefFor(AREA_PAGE_SEGMENT.FINDINGS),
    "Findings",
    ListChecks,
    pathname,
  );
  const triage = isCloudsneekerFeatureEnabled("findingTriage")
    ? productLink(
        hrefFor(AREA_PAGE_SEGMENT.TRIAGE),
        "Triage",
        ClipboardCheck,
        pathname,
      )
    : undefined;
  const hub = productLink(hubHref, hubLabel, hubIcon, pathname);
  hub.active = hub.active && !findings.active && !triage?.active;
  return [hub, findings, ...(triage ? [triage] : [])];
};

const childLink = (
  href: string,
  label: string,
  pathname: string,
): NavigationChildLink => ({
  kind: NAVIGATION_ITEM_KIND.LINK,
  href,
  label,
  active: isRouteActive(pathname, href),
});

const collapsible = (
  label: string,
  icon: LucideIcon,
  children: NavigationChildLink[],
  open = false,
): NavigationCollapsible => ({
  kind: NAVIGATION_ITEM_KIND.COLLAPSIBLE,
  label,
  icon,
  children,
  defaultOpen: open || children.some((child) => child.active),
});

/**
 * Application Security: overview, application inventory, scans, then the
 * finding workspaces, the software inventory and scan setup as groups.
 * Target and scan pages (`/application-security/<id>/...`) belong to Scans.
 */
const appSecurityItems = (pathname: string): NavigationItem[] => {
  const hubHref = PRODUCT_ROUTE.APPLICATION_SECURITY;
  const segment = pathname.startsWith(`${hubHref}/`)
    ? (pathname.slice(hubHref.length + 1).split("/")[0] ?? "")
    : "";
  const onTargetPage =
    segment !== "" &&
    (segment === "new" || !APPSEC_RESERVED_SEGMENTS.includes(segment));

  const overview = productLink(
    hubHref,
    BRAND.appSecurityName,
    ShieldCheck,
    pathname,
  );
  overview.active = pathname === hubHref;
  const scans = productLink(
    appSecurityHref(APPSEC_SEGMENT.SCANS),
    "Scans",
    ScanSearch,
    pathname,
  );
  scans.active = scans.active || onTargetPage;

  const findings = APPSEC_WORKSPACES.map((workspace) =>
    childLink(appSecurityHref(workspace.segment), workspace.title, pathname),
  );
  if (isCloudsneekerFeatureEnabled("findingTriage")) {
    findings.push(
      childLink(appSecurityHref(AREA_PAGE_SEGMENT.TRIAGE), "Triage", pathname),
    );
  }

  return [
    overview,
    productLink(
      appSecurityHref(APPSEC_SEGMENT.APPLICATIONS),
      "Applications",
      Boxes,
      pathname,
    ),
    scans,
    collapsible("Findings", ShieldAlert, findings, true),
    collapsible("Software inventory", Package, [
      childLink(
        appSecurityHref(APPSEC_SEGMENT.COMPONENTS),
        "Components",
        pathname,
      ),
      childLink(appSecurityHref(APPSEC_SEGMENT.SBOMS), "SBOMs", pathname),
    ]),
    collapsible("Scan setup", SlidersHorizontal, [
      childLink(
        appSecurityHref(APPSEC_SEGMENT.PROFILES),
        "Scan profiles",
        pathname,
      ),
      childLink(
        appSecurityHref(APPSEC_SEGMENT.SETTINGS),
        "Engine and policies",
        pathname,
      ),
    ]),
  ];
};

const sectionOrNull = (
  label: string | undefined,
  items: (NavigationItem | undefined)[],
): NavigationSection | null => {
  const present = items.filter(
    (item): item is NavigationItem => item !== undefined,
  );
  if (present.length === 0) return null;
  return label === undefined ? { items: present } : { label, items: present };
};

export const withCloudsneekerNavigation = (
  sections: NavigationSection[],
  pathname: string,
  plan: NavigationPlanState = UNKNOWN_PLAN,
): NavigationSection[] =>
  withCloudsneekerPlan(regroupNavigation(sections, pathname), plan);

/**
 * Applies the organization plan to the finished sidebar: the operator
 * console link for platform operators, then hides features outside the plan.
 * The sidebar calls it with the plan store value (one `cloudsneeker-hook`)
 * so a plan change is an input of the render, not hidden module state.
 */
export const withCloudsneekerPlan = (
  sections: NavigationSection[],
  plan: NavigationPlanState,
): NavigationSection[] =>
  filterNavigationByPlan(withOperatorConsoleLink(sections, plan), plan);

const withOperatorConsoleLink = (
  sections: NavigationSection[],
  plan: NavigationPlanState,
): NavigationSection[] => {
  if (!plan.isOperator) return sections;
  return sections.map((section) => ({
    ...section,
    items: section.items.map((item) =>
      item.kind === NAVIGATION_ITEM_KIND.COLLAPSIBLE &&
      item.label === UPSTREAM_COLLAPSIBLE_LABEL.ORGANIZATION &&
      !item.children.some(
        (entry) => entry.label === OPERATOR_CONSOLE_CHILD.label,
      )
        ? { ...item, children: [...item.children, OPERATOR_CONSOLE_CHILD] }
        : item,
    ),
  }));
};

/**
 * Hides links (and emptied collapsibles and sections) whose feature is not
 * in the plan. Nothing is hidden while the plan is unknown.
 */
export const filterNavigationByPlan = (
  sections: NavigationSection[],
  plan: NavigationPlanState,
): NavigationSection[] => {
  const { features } = plan;
  if (features === null) return sections;
  const result: NavigationSection[] = [];
  for (const section of sections) {
    const items: NavigationItem[] = [];
    for (const item of section.items) {
      if (item.kind === NAVIGATION_ITEM_KIND.LINK) {
        if (isHrefInPlan(item.href, features)) items.push(item);
        continue;
      }
      const children = item.children.filter(
        (child) =>
          child.kind !== NAVIGATION_ITEM_KIND.LINK ||
          isHrefInPlan(child.href, features),
      );
      if (children.length > 0) items.push({ ...item, children });
    }
    if (items.length > 0) result.push({ ...section, items });
  }
  return result;
};

const regroupNavigation = (
  sections: NavigationSection[],
  pathname: string,
): NavigationSection[] => {
  const upstream = indexUpstream(sections, pathname);
  const placed = new Set<NavigationItem>();

  const takeLink = (path: string): NavigationLink | undefined => {
    const match = upstream.items.find(
      ({ item }) =>
        item.kind === NAVIGATION_ITEM_KIND.LINK &&
        !placed.has(item) &&
        hrefPath(item.href) === path,
    )?.item;
    if (!match || match.kind !== NAVIGATION_ITEM_KIND.LINK) return undefined;
    placed.add(match);
    return match;
  };

  const placedChildren = new Set<NavigationChild>();
  const takeChild = (href: string): NavigationChildLink | undefined => {
    const match = upstream.configurationChildren.find(
      (child) =>
        child.kind === NAVIGATION_ITEM_KIND.LINK &&
        !placedChildren.has(child) &&
        child.href === href,
    );
    if (!match || match.kind !== NAVIGATION_ITEM_KIND.LINK) return undefined;
    placedChildren.add(match);
    return match;
  };

  const leftovers = (sectionLabel: string | undefined): NavigationItem[] =>
    upstream.items
      .filter(
        ({ item, sectionLabel: from }) =>
          !placed.has(item) && from === sectionLabel,
      )
      .map(({ item }) => item);

  // Overview and the assistant.
  const assistant = takeLink("/lighthouse");
  const overviewItems = [
    takeLink("/"),
    assistant ? { ...assistant, label: BRAND.assistantName } : undefined,
  ];

  const cloudSecurityItems = [
    takeLink("/findings"),
    // --- Finding triage (EB-010) ---
    isCloudsneekerFeatureEnabled("findingTriage")
      ? productLink(
          PRODUCT_ROUTE.FINDING_TRIAGE,
          "Triage",
          ClipboardCheck,
          pathname,
        )
      : undefined,
    // --- End finding triage (EB-010) ---
    takeLink("/resources"),
    takeLink("/attack-paths"),
    takeLink("/compliance"),
  ];

  const applicationSecurity = isCloudsneekerFeatureEnabled("trivy")
    ? sectionOrNull(
        NAVIGATION_SECTION_LABEL.APPLICATION_SECURITY,
        appSecurityItems(pathname),
      )
    : null;

  const governance = isCloudsneekerFeatureEnabled("custodian")
    ? sectionOrNull(
        NAVIGATION_SECTION_LABEL.GOVERNANCE,
        areaLinks(
          PRODUCT_ROUTE.GOVERNANCE,
          BRAND.governanceName,
          Scale,
          governanceHref,
          pathname,
        ),
      )
    : null;

  const reports = isCloudsneekerFeatureEnabled("reports")
    ? sectionOrNull(NAVIGATION_SECTION_LABEL.REPORTS, [
        productLink(PRODUCT_ROUTE.REPORTS, "Reports", FileBarChart, pathname),
      ])
    : null;

  const operationsItems: (NavigationItem | undefined)[] = [takeLink("/scans")];
  for (const link of OPERATIONS_LINKS) {
    const child = takeChild(link.href);
    if (!child) continue;
    operationsItems.push({
      kind: NAVIGATION_ITEM_KIND.LINK,
      href: child.href,
      label: link.label,
      icon: link.icon,
      active: isRouteActive(pathname, child.href),
      highlight: child.highlight,
      requiredPermission: child.requiredPermission,
    });
  }

  // Settings: sources, policies applied to scans, connected apps, assistant.
  const relabel = (
    child: NavigationChildLink | undefined,
    label: string,
  ): NavigationChildLink | undefined =>
    child ? { ...child, label } : undefined;

  const configurationChildren: NavigationChild[] = [
    relabel(takeChild("/providers"), SETTINGS_CHILD_LABEL.SOURCES),
    takeChild("/mutelist"),
    takeChild("/integrations"),
    relabel(
      takeChild("/lighthouse/settings"),
      SETTINGS_CHILD_LABEL.ASSISTANT_SETTINGS,
    ),
  ].filter((child): child is NavigationChildLink => child !== undefined);
  // Upstream additions to Configuration stay reachable there.
  configurationChildren.push(
    ...upstream.configurationChildren.filter(
      (child) => !placedChildren.has(child),
    ),
  );

  const configuration: NavigationCollapsible | undefined =
    upstream.configuration && configurationChildren.length > 0
      ? { ...upstream.configuration, children: configurationChildren }
      : undefined;

  const withProductChild = (
    children: NavigationChild[],
    productChild: NavigationChildLink,
    position: "start" | "end",
  ): NavigationChild[] => {
    if (children.some((entry) => entry.label === productChild.label)) {
      return children;
    }
    const entry = {
      ...productChild,
      active: isRouteActive(pathname, productChild.href),
    };
    return position === "start" ? [entry, ...children] : [...children, entry];
  };

  const organization: NavigationCollapsible | undefined = upstream.organization
    ? {
        ...upstream.organization,
        children: withProductChild(
          withProductChild(
            withProductChild(
              withProductChild(
                withProductChild(
                  upstream.organization.children,
                  SECURITY_CHILD,
                  "start",
                ),
                PROFILE_CHILD,
                "start",
              ),
              CONTENT_VERSIONS_CHILD,
              "end",
            ),
            RELEASE_NOTES_CHILD,
            "end",
          ),
          AUDIT_LOG_CHILD,
          "end",
        ),
      }
    : undefined;

  // Items upstream adds later stay in the matching product section.
  const result: (NavigationSection | null)[] = [
    sectionOrNull(undefined, [...overviewItems, ...leftovers(undefined)]),
    sectionOrNull(NAVIGATION_SECTION_LABEL.CLOUD_SECURITY, [
      ...cloudSecurityItems,
      ...leftovers(UPSTREAM_SECTION_LABEL.SECURITY),
    ]),
    applicationSecurity,
    governance,
    reports,
    sectionOrNull(NAVIGATION_SECTION_LABEL.OPERATIONS, operationsItems),
    sectionOrNull(NAVIGATION_SECTION_LABEL.SETTINGS, [
      configuration,
      organization,
      ...leftovers(UPSTREAM_SECTION_LABEL.SETTINGS),
    ]),
  ];

  // Sections Cloudsneeker does not regroup keep their items at the end.
  const known = new Set<string | undefined>([
    undefined,
    UPSTREAM_SECTION_LABEL.SECURITY,
    UPSTREAM_SECTION_LABEL.SETTINGS,
    UPSTREAM_SECTION_LABEL.HELP,
  ]);
  for (const section of sections) {
    if (known.has(section.label)) continue;
    const items = leftovers(section.label);
    if (items.length > 0) result.push({ ...section, items });
  }

  return result.filter(
    (section): section is NavigationSection => section !== null,
  );
};
