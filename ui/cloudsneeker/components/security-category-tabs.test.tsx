import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { securityCategoryTabs } from "@/cloudsneeker/lib/app-security-categories";
import {
  AREA_FINDING_SORT,
  type AreaFindingFilters,
} from "@/cloudsneeker/lib/area-findings";
import { FINDING_AREA } from "@/cloudsneeker/types/area-findings";

import { SecurityCategoryTabs } from "./security-category-tabs";

const filters: AreaFindingFilters = {
  severities: ["critical"],
  triage: null,
  source: null,
  search: "",
  sort: AREA_FINDING_SORT.SEVERITY,
  page: 3,
  fix: null,
  category: "sca",
};

describe("SecurityCategoryTabs", () => {
  it("links each enabled category and keeps the other filters", () => {
    render(
      <SecurityCategoryTabs
        area={FINDING_AREA.APPLICATION_SECURITY}
        filters={filters}
        tabs={securityCategoryTabs({ sca: 5, secrets: 2 }, ["sca", "secrets"])}
      />,
    );

    const all = screen.getByRole("link", { name: /All categories/ });
    expect(all).toHaveTextContent("7");
    expect(all).toHaveAttribute(
      "href",
      "/application-security/findings?filter%5Bseverity__in%5D=critical",
    );
    const sca = screen.getByRole("link", { name: /SCA/ });
    expect(sca).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: /Secrets/ })).toHaveAttribute(
      "href",
      "/application-security/findings?filter%5Bseverity__in%5D=critical&category=secrets",
    );
  });

  it("marks categories no target runs as not enabled, without a link", () => {
    render(
      <SecurityCategoryTabs
        area={FINDING_AREA.APPLICATION_SECURITY}
        filters={{ ...filters, category: undefined }}
        tabs={securityCategoryTabs({}, ["sca"])}
      />,
    );

    expect(screen.queryByRole("link", { name: /SAST/ })).toBeNull();
    expect(screen.getAllByText("Not enabled")).toHaveLength(4);
    expect(screen.getByText(/Not integrated: Dynamic testing/)).toBeVisible();
  });
});
