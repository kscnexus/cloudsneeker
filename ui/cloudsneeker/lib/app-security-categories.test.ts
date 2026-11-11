import { describe, expect, it } from "vitest";

import {
  areaFindingsPageHref,
  areaFindingsSearchParams,
  parseAreaFilters,
} from "@/cloudsneeker/lib/area-findings";
import { FINDING_AREA } from "@/cloudsneeker/types/area-findings";

import {
  categoryTotal,
  securityCategoryShort,
  securityCategoryTabs,
} from "./app-security-categories";

describe("securityCategoryTabs", () => {
  it("lists every category in order with counts that add up", () => {
    const tabs = securityCategoryTabs({ sca: 4, secrets: 1, iac: 2 }, [
      "sca",
      "secrets",
      "iac",
      "sast",
    ]);
    expect(tabs.map((tab) => tab.category)).toEqual([
      "sast",
      "sca",
      "secrets",
      "iac",
      "container",
    ]);
    expect(categoryTotal(tabs)).toBe(7);
    expect(tabs.find((tab) => tab.category === "sast")).toMatchObject({
      count: 0,
      enabled: true,
    });
    expect(tabs.find((tab) => tab.category === "container")?.enabled).toBe(
      false,
    );
  });

  it("enables a category that has findings even without a target for it", () => {
    const tabs = securityCategoryTabs({ container: 3 }, []);
    expect(tabs.find((tab) => tab.category === "container")?.enabled).toBe(
      true,
    );
  });

  it("copes with a response without category meta", () => {
    expect(categoryTotal(securityCategoryTabs(undefined, undefined))).toBe(0);
  });
});

describe("securityCategoryShort", () => {
  it("labels known categories and dashes the rest", () => {
    expect(securityCategoryShort("sca")).toBe("SCA");
    expect(securityCategoryShort("iac")).toBe("IaC");
    expect(securityCategoryShort("")).toBe("—");
    expect(securityCategoryShort(undefined)).toBe("—");
  });
});

describe("category filter", () => {
  it("reads the category from the URL and sends it for Application Security", () => {
    const filters = parseAreaFilters({ category: "Secrets" });
    expect(filters.category).toBe("secrets");
    expect(
      areaFindingsSearchParams(FINDING_AREA.APPLICATION_SECURITY, filters)[
        "filter[category__in]"
      ],
    ).toBe("secrets");
    expect(
      areaFindingsPageHref(FINDING_AREA.APPLICATION_SECURITY, filters),
    ).toBe("/application-security/findings?category=secrets");
  });

  it("drops unknown categories and other areas", () => {
    expect(parseAreaFilters({ category: "dast" }).category).toBeUndefined();
    const filters = parseAreaFilters({ category: "sast" });
    expect(
      areaFindingsSearchParams(FINDING_AREA.CLOUD, filters)[
        "filter[category__in]"
      ],
    ).toBeUndefined();
  });
});
