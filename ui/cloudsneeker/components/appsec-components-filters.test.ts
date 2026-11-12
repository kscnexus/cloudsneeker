import { describe, expect, it } from "vitest";

import {
  buildComponentFilters,
  componentsHref,
  componentsQuery,
  parseComponentFilters,
} from "./appsec-components-table";

describe("component list filters", () => {
  it("reads the filter bar names and the earlier ones", () => {
    const filters = parseComponentFilters({
      "filter[ecosystem]": "npm",
      "filter[vulnerable]": "true",
      relationship: "direct",
      q: "lodash",
      sort: "name",
    });
    expect(filters).toMatchObject({
      ecosystem: "npm",
      vulnerable: true,
      relationship: "direct",
      search: "lodash",
      sort: "name",
    });
    expect(componentsQuery(filters)).toMatchObject({
      "filter[ecosystem]": "npm",
      "filter[vulnerable]": "true",
      "filter[relationship]": "direct",
      "filter[search]": "lodash",
    });
  });

  it("writes links with the filter bar names and keeps the scope", () => {
    expect(
      componentsHref(
        "/application-security/components",
        { vulnerable: true, page: 2 },
        { target: "t1" },
      ),
    ).toBe(
      "/application-security/components?target=t1&filter%5Bvulnerable%5D=true&page=2",
    );
  });

  it("offers ecosystems and licenses as dropdowns", () => {
    const filters = buildComponentFilters({
      ecosystems: ["npm", ""],
      licenses: ["MIT"],
    });
    expect(filters.map((filter) => filter.label)).toEqual([
      "Ecosystems",
      "Relationships",
      "Vulnerability states",
      "Licenses",
      "License statements",
    ]);
    expect(filters[0].options).toEqual([
      { value: "npm", label: "npm" },
      { value: "", label: "unknown" },
    ]);
  });
});
