import { Info } from "lucide-react";
import { describe, expect, it } from "vitest";

import {
  NAVIGATION_ITEM_KIND,
  type NavigationSection,
} from "@/components/layout/app-sidebar/types";

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
});
