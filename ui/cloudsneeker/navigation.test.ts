import { Info } from "lucide-react";
import { describe, expect, it } from "vitest";

import {
  NAVIGATION_ITEM_KIND,
  type NavigationSection,
} from "@/components/layout/app-sidebar/types";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import { withCloudsneekerNavigation } from "./navigation";

const upstreamSections = (): NavigationSection[] => [
  {
    items: [
      {
        kind: NAVIGATION_ITEM_KIND.LINK,
        href: "/",
        label: "Overview",
        icon: Info,
      },
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

describe("withCloudsneekerNavigation", () => {
  it("removes the HELP section and keeps the other sections", () => {
    const sections = upstreamSections();

    const result = withCloudsneekerNavigation(sections, "/");

    expect(result.map((section) => section.label ?? null)).toEqual([null]);
    expect(result[0]).toBe(sections[0]);
  });

  it("leaves navigation unchanged when there is no HELP section", () => {
    const [overview] = upstreamSections();

    const result = withCloudsneekerNavigation(
      [overview as NavigationSection],
      "/",
    );

    expect(result).toEqual([overview]);
  });

  it("does not mutate the upstream sections", () => {
    const sections = upstreamSections();
    const helpItemCount = sections[1]?.items.length;

    withCloudsneekerNavigation(sections, "/");

    expect(sections).toHaveLength(2);
    expect(sections[1]?.items).toHaveLength(helpItemCount ?? -1);
  });

  it("adds Profile under Organization", () => {
    const sections: NavigationSection[] = [
      {
        label: "SETTINGS",
        items: [
          {
            kind: NAVIGATION_ITEM_KIND.COLLAPSIBLE,
            label: "Organization",
            icon: Info,
            defaultOpen: false,
            children: [
              {
                kind: NAVIGATION_ITEM_KIND.LINK,
                href: "/users",
                label: "Users",
              },
              {
                kind: NAVIGATION_ITEM_KIND.LINK,
                href: "/roles",
                label: "Roles",
              },
            ],
          },
        ],
      },
    ];

    const result = withCloudsneekerNavigation(sections, "/profile");

    expect(result[0]?.items[0]).toMatchObject({
      children: [
        {
          label: "Profile",
          href: "/profile",
          kind: NAVIGATION_ITEM_KIND.LINK,
          active: true,
        },
        { label: "Users", href: "/users" },
        { label: "Roles", href: "/roles" },
      ],
    });
  });

  it("turns cloud-only configuration controls into working product links", () => {
    const sections: NavigationSection[] = [
      {
        label: "CONFIGURATION",
        items: [
          {
            kind: NAVIGATION_ITEM_KIND.COLLAPSIBLE,
            label: "Configuration",
            icon: Info,
            defaultOpen: true,
            children: [
              {
                kind: NAVIGATION_ITEM_KIND.LINK,
                href: "/providers",
                label: "Providers",
              },
              {
                kind: NAVIGATION_ITEM_KIND.CLOUD_UPGRADE,
                label: "Alerts",
                cloudUpgradeFeature: CLOUD_UPGRADE_FEATURE.ALERTS,
              },
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
              },
            ],
          },
        ],
      },
    ];

    const result = withCloudsneekerNavigation(sections, "/alerts");

    expect(result[0]?.items[0]).toMatchObject({
      children: [
        {
          label: "Cloud Custodian",
          href: "/custodian",
          kind: NAVIGATION_ITEM_KIND.LINK,
        },
        { label: "Providers", href: "/providers" },
        { label: "Alerts", href: "/alerts", kind: NAVIGATION_ITEM_KIND.LINK },
        {
          label: "Scan profiles",
          href: "/scans/config",
          kind: NAVIGATION_ITEM_KIND.LINK,
        },
        {
          label: "CLI Import",
          href: "/scans?import=1",
          kind: NAVIGATION_ITEM_KIND.LINK,
        },
        { label: "Integrations", href: "/integrations" },
      ],
    });
    expect(sections[0]?.items[0]).toMatchObject({
      children: [
        { label: "Providers" },
        { label: "Alerts", kind: NAVIGATION_ITEM_KIND.CLOUD_UPGRADE },
        { label: "Scans", kind: NAVIGATION_ITEM_KIND.CLOUD_UPGRADE },
        { label: "CLI Import", kind: NAVIGATION_ITEM_KIND.CLOUD_UPGRADE },
        { label: "Integrations" },
      ],
    });
  });

  it("marks Cloud Custodian active on custodian routes", () => {
    const sections: NavigationSection[] = [
      {
        label: "SETTINGS",
        items: [
          {
            kind: NAVIGATION_ITEM_KIND.COLLAPSIBLE,
            label: "Configuration",
            icon: Info,
            defaultOpen: true,
            children: [
              {
                kind: NAVIGATION_ITEM_KIND.LINK,
                href: "/providers",
                label: "Providers",
              },
            ],
          },
        ],
      },
    ];

    const result = withCloudsneekerNavigation(sections, "/custodian/abc");

    expect(result[0]?.items[0]).toMatchObject({
      children: [
        {
          label: "Cloud Custodian",
          href: "/custodian",
          active: true,
        },
        { label: "Providers", href: "/providers" },
      ],
    });
  });
});
