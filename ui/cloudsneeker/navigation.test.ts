import { Info } from "lucide-react";
import { describe, expect, it } from "vitest";

import {
  NAVIGATION_ITEM_KIND,
  type NavigationSection,
} from "@/components/layout/app-sidebar/types";

import {
  CLOUDSNEEKER_ROUTE,
  getCloudsneekerNavigationItems,
  withCloudsneekerNavigation,
} from "./navigation";

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

describe("getCloudsneekerNavigationItems", () => {
  it("links to the About page and marks it active on its route", () => {
    // When
    const items = getCloudsneekerNavigationItems(CLOUDSNEEKER_ROUTE.ABOUT);

    // Then
    expect(items).toHaveLength(1);
    expect(items[0]).toEqual(
      expect.objectContaining({
        kind: NAVIGATION_ITEM_KIND.LINK,
        href: CLOUDSNEEKER_ROUTE.ABOUT,
        label: "About Cloudsneeker",
        active: true,
      }),
    );
  });

  it("is inactive on other routes", () => {
    expect(getCloudsneekerNavigationItems("/findings")[0]).toEqual(
      expect.objectContaining({ active: false }),
    );
  });

  it("never mentions the upstream product", () => {
    const labels = getCloudsneekerNavigationItems("/").map(
      (item) => item.label,
    );
    expect(labels.join(" ")).not.toMatch(/prowler/i);
  });
});

describe("withCloudsneekerNavigation", () => {
  it("appends the items to the HELP section and keeps the other sections intact", () => {
    // Given
    const sections = upstreamSections();

    // When
    const result = withCloudsneekerNavigation(sections, "/");

    // Then
    expect(result.map((section) => section.label ?? null)).toEqual([
      null,
      "HELP",
    ]);
    expect(result[0]).toBe(sections[0]);
    expect(result[1]?.items.map((item) => item.label)).toEqual([
      "Documentation",
      "About Cloudsneeker",
    ]);
  });

  it("adds a HELP section when upstream does not have one", () => {
    // Given
    const [overview] = upstreamSections();

    // When
    const result = withCloudsneekerNavigation(
      [overview as NavigationSection],
      "/",
    );

    // Then
    expect(result.map((section) => section.label ?? null)).toEqual([
      null,
      "HELP",
    ]);
    expect(result[1]?.items.map((item) => item.label)).toEqual([
      "About Cloudsneeker",
    ]);
  });

  it("does not mutate the upstream sections", () => {
    const sections = upstreamSections();
    const helpItemCount = sections[1]?.items.length;

    withCloudsneekerNavigation(sections, "/");

    expect(sections[1]?.items).toHaveLength(helpItemCount ?? -1);
  });
});
