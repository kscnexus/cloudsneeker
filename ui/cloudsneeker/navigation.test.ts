import { Info } from "lucide-react";
import { describe, expect, it } from "vitest";

import {
  NAVIGATION_ITEM_KIND,
  NAVIGATION_PERMISSION,
  type NavigationChild,
  type NavigationItem,
  type NavigationSection,
} from "@/components/layout/app-sidebar/types";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { BRAND } from "./brand";
import {
  NAVIGATION_SECTION_LABEL,
  withCloudsneekerNavigation,
} from "./navigation";

const link = (
  href: string,
  label: string,
  active = false,
): NavigationItem => ({
  kind: NAVIGATION_ITEM_KIND.LINK,
  href,
  label,
  icon: Info,
  active,
});

const child = (href: string, label: string): NavigationChild => ({
  kind: NAVIGATION_ITEM_KIND.LINK,
  href,
  label,
});

// Mirrors the Local Server sections built by upstream `navigation-config.ts`.
const upstreamSections = (
  extras: { security?: NavigationItem[]; settings?: NavigationItem[] } = {},
): NavigationSection[] => [
  {
    items: [link("/", "Overview"), link("/lighthouse", "Lighthouse AI")],
  },
  {
    label: "SECURITY",
    items: [
      link("/compliance", "Compliance"),
      link(
        "/findings?filter[muted]=false&filter[status__in]=FAIL",
        "Findings",
      ),
      link("/attack-paths", "Attack Paths"),
      link("/scans", "Scans"),
      link("/resources", "Resources"),
      ...(extras.security ?? []),
    ],
  },
  {
    label: "SETTINGS",
    items: [
      {
        kind: NAVIGATION_ITEM_KIND.COLLAPSIBLE,
        label: "Configuration",
        icon: Info,
        defaultOpen: true,
        children: [
          child("/providers", "Providers"),
          {
            kind: NAVIGATION_ITEM_KIND.CLOUD_UPGRADE,
            label: "Alerts",
            cloudUpgradeFeature: CLOUD_UPGRADE_FEATURE.ALERTS,
          },
          child("/mutelist", "Mutelist"),
          {
            kind: NAVIGATION_ITEM_KIND.CLOUD_UPGRADE,
            label: "Scans",
            cloudUpgradeFeature: CLOUD_UPGRADE_FEATURE.SCAN_CONFIGURATION,
          },
          {
            kind: NAVIGATION_ITEM_KIND.CLOUD_UPGRADE,
            label: "CLI Import",
            cloudUpgradeFeature: CLOUD_UPGRADE_FEATURE.CLI_IMPORT,
          },
          {
            kind: NAVIGATION_ITEM_KIND.LINK,
            href: "/integrations",
            label: "Integrations",
            requiredPermission: NAVIGATION_PERMISSION.MANAGE_INTEGRATIONS,
          },
          child("/lighthouse/settings", "Lighthouse AI"),
        ],
      },
      {
        kind: NAVIGATION_ITEM_KIND.COLLAPSIBLE,
        label: "Organization",
        icon: Info,
        defaultOpen: false,
        children: [
          child("/users", "Users"),
          child("/invitations", "Invitations"),
          child("/roles", "Roles"),
        ],
      },
      ...(extras.settings ?? []),
    ],
  },
  {
    label: "HELP",
    items: [
      {
        kind: NAVIGATION_ITEM_KIND.LINK,
        href: "https://docs.example",
        label: "Documentation",
        icon: Info,
        target: "_blank",
      },
    ],
  },
];

const labelsOf = (sections: NavigationSection[]) =>
  sections.map((section) => ({
    label: section.label ?? null,
    items: section.items.map((item) => item.label),
  }));

const findItem = (sections: NavigationSection[], label: string) =>
  sections
    .flatMap((section) => section.items)
    .find((item) => item.label === label);

const childrenOf = (sections: NavigationSection[], label: string) => {
  const item = findItem(sections, label);
  if (item?.kind !== NAVIGATION_ITEM_KIND.COLLAPSIBLE) {
    throw new Error(`${label} must be a collapsible navigation item`);
  }
  return item.children;
};

const allLabels = (sections: NavigationSection[]): string[] =>
  sections.flatMap((section) => [
    section.label ?? "",
    ...section.items.flatMap((item) =>
      item.kind === NAVIGATION_ITEM_KIND.COLLAPSIBLE
        ? [item.label, ...item.children.map((entry) => entry.label)]
        : [item.label],
    ),
  ]);

describe("withCloudsneekerNavigation", () => {
  it("groups the sidebar into one product structure", () => {
    const result = withCloudsneekerNavigation(upstreamSections(), "/");

    expect(labelsOf(result)).toEqual([
      { label: null, items: ["Overview", BRAND.assistantName] },
      {
        label: NAVIGATION_SECTION_LABEL.CLOUD_SECURITY,
        items: ["Findings", "Resources", "Attack Paths", "Compliance"],
      },
      {
        label: NAVIGATION_SECTION_LABEL.APPLICATION_SECURITY,
        items: [BRAND.appSecurityName],
      },
      {
        label: NAVIGATION_SECTION_LABEL.GOVERNANCE,
        items: [BRAND.governanceName],
      },
      {
        label: NAVIGATION_SECTION_LABEL.REPORTS,
        items: ["Reports"],
      },
      {
        label: NAVIGATION_SECTION_LABEL.OPERATIONS,
        items: ["Scans", "Alerts", "Scan profiles", "CLI Import"],
      },
      {
        label: NAVIGATION_SECTION_LABEL.SETTINGS,
        items: ["Configuration", "Organization"],
      },
    ]);
  });

  it("never shows engine names and keeps product areas top-level", () => {
    const result = withCloudsneekerNavigation(upstreamSections(), "/");

    for (const label of allLabels(result)) {
      expect(label).not.toMatch(/trivy|custodian|c7n|prowler|lighthouse/i);
    }

    expect(findItem(result, BRAND.appSecurityName)).toMatchObject({
      kind: NAVIGATION_ITEM_KIND.LINK,
      href: "/application-security",
    });
    expect(findItem(result, BRAND.governanceName)).toMatchObject({
      kind: NAVIGATION_ITEM_KIND.LINK,
      href: "/governance",
    });

    const configurationHrefs = childrenOf(result, "Configuration").map(
      (entry) => (entry.kind === NAVIGATION_ITEM_KIND.LINK ? entry.href : ""),
    );
    expect(configurationHrefs).not.toContain("/application-security");
    expect(configurationHrefs).not.toContain("/governance");
    expect(
      configurationHrefs.some((href) => /trivy|custodian/.test(href)),
    ).toBe(false);
  });

  it("keeps Configuration to settings-only children", () => {
    const sections = upstreamSections();
    const result = withCloudsneekerNavigation(sections, "/providers");
    const children = childrenOf(result, "Configuration");

    expect(children).toEqual([
      expect.objectContaining({
        label: "Sources & Providers",
        href: "/providers",
      }),
      expect.objectContaining({ label: "Mutelist", href: "/mutelist" }),
      expect.objectContaining({
        label: "Integrations",
        href: "/integrations",
        requiredPermission: NAVIGATION_PERMISSION.MANAGE_INTEGRATIONS,
      }),
      expect.objectContaining({
        label: `${BRAND.assistantName} settings`,
        href: "/lighthouse/settings",
      }),
    ]);

    // Unchanged upstream children are reused, not copied.
    const upstreamConfiguration = sections[2]?.items[0];
    if (upstreamConfiguration?.kind !== NAVIGATION_ITEM_KIND.COLLAPSIBLE) {
      throw new Error("fixture Configuration missing");
    }
    expect(children[1]).toBe(upstreamConfiguration.children[2]);
  });

  it("turns cloud-only controls into Operations links", () => {
    const result = withCloudsneekerNavigation(upstreamSections(), "/alerts");
    const operations = result.find(
      (section) => section.label === NAVIGATION_SECTION_LABEL.OPERATIONS,
    );

    expect(operations?.items).toEqual([
      expect.objectContaining({ label: "Scans", href: "/scans" }),
      expect.objectContaining({
        kind: NAVIGATION_ITEM_KIND.LINK,
        label: "Alerts",
        href: "/alerts",
        active: true,
        highlight: true,
      }),
      expect.objectContaining({
        label: "Scan profiles",
        href: "/scans/config",
        active: false,
      }),
      expect.objectContaining({
        label: "CLI Import",
        href: "/scans?import=1",
        active: false,
      }),
    ]);
    for (const item of operations?.items ?? []) {
      expect(item.icon).toBeDefined();
    }
  });

  it("marks the product areas active on their routes", () => {
    const appSecurity = withCloudsneekerNavigation(
      upstreamSections(),
      "/application-security/abc/runs/def",
    );
    expect(findItem(appSecurity, BRAND.appSecurityName)).toMatchObject({
      active: true,
    });
    expect(findItem(appSecurity, BRAND.governanceName)).toMatchObject({
      active: false,
    });

    const governance = withCloudsneekerNavigation(
      upstreamSections(),
      "/governance",
    );
    expect(findItem(governance, BRAND.governanceName)).toMatchObject({
      active: true,
    });
  });

  it("links Reports between Governance and Operations", () => {
    const result = withCloudsneekerNavigation(upstreamSections(), "/reports/run-1");
    const labels = result.map((section) => section.label);

    expect(labels.indexOf(NAVIGATION_SECTION_LABEL.REPORTS)).toBe(
      labels.indexOf(NAVIGATION_SECTION_LABEL.GOVERNANCE) + 1,
    );
    expect(labels.indexOf(NAVIGATION_SECTION_LABEL.OPERATIONS)).toBe(
      labels.indexOf(NAVIGATION_SECTION_LABEL.REPORTS) + 1,
    );
    expect(findItem(result, "Reports")).toMatchObject({
      kind: NAVIGATION_ITEM_KIND.LINK,
      href: "/reports",
      active: true,
    });
    expect(findItem(result, "Reports")?.icon).toBeDefined();
  });

  it("adds Profile under Organization", () => {
    const result = withCloudsneekerNavigation(upstreamSections(), "/profile");

    expect(childrenOf(result, "Organization")).toEqual([
      expect.objectContaining({
        label: "Profile",
        href: "/profile",
        kind: NAVIGATION_ITEM_KIND.LINK,
        active: true,
      }),
      expect.objectContaining({ label: "Users", href: "/users" }),
      expect.objectContaining({ label: "Invitations", href: "/invitations" }),
      expect.objectContaining({ label: "Roles", href: "/roles" }),
    ]);
  });

  it("removes HELP and does not mutate the upstream sections", () => {
    const sections = upstreamSections();
    const before = structuredClone(
      sections.map((section) => ({
        label: section.label,
        items: section.items.map((item) => item.label),
      })),
    );

    const result = withCloudsneekerNavigation(sections, "/");

    expect(result.some((section) => section.label === "HELP")).toBe(false);
    expect(findItem(result, "Documentation")).toBeUndefined();
    expect(
      sections.map((section) => ({
        label: section.label,
        items: section.items.map((item) => item.label),
      })),
    ).toEqual(before);
    expect(childrenOf(sections, "Configuration")[0]).toMatchObject({
      label: "Providers",
    });
  });

  it("keeps items upstream adds in the matching product section", () => {
    const result = withCloudsneekerNavigation(
      upstreamSections({
        security: [link("/registry", "Registry")],
        settings: [link("/billing", "Billing")],
      }),
      "/",
    );

    const itemLabels = (label: string) =>
      result
        .find((section) => section.label === label)
        ?.items.map((item) => item.label);

    expect(itemLabels(NAVIGATION_SECTION_LABEL.CLOUD_SECURITY)).toEqual([
      "Findings",
      "Resources",
      "Attack Paths",
      "Compliance",
      "Registry",
    ]);
    expect(itemLabels(NAVIGATION_SECTION_LABEL.SETTINGS)).toEqual([
      "Configuration",
      "Organization",
      "Billing",
    ]);
  });

  it("omits the assistant when upstream does not offer it", () => {
    const sections = upstreamSections();
    sections[0] = { items: [link("/", "Overview", true)] };

    const result = withCloudsneekerNavigation(sections, "/");

    expect(result[0]?.items.map((item) => item.label)).toEqual(["Overview"]);
  });
});
