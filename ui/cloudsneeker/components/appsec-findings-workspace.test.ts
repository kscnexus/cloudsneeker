import { describe, expect, it, vi } from "vitest";

vi.mock("@/cloudsneeker/actions/appsec", () => ({}));
vi.mock("@/cloudsneeker/lib/trivy-targets-data", () => ({}));
vi.mock("@/components/shadcn/content-layout", () => ({}));
vi.mock("./area-triage-view", () => ({ pagesOf: () => 1 }));
vi.mock("next/navigation", () => ({ redirect: vi.fn() }));

import {
  APPSEC_FINDING_PARAM,
  APPSEC_WORKSPACES,
} from "@/cloudsneeker/lib/appsec";

import { buildAppSecFilters } from "./appsec-findings-workspace";

const workspace = APPSEC_WORKSPACES[0];

const keys = (filters: { key: string }[]) =>
  filters.map((filter) => filter.key);

describe("buildAppSecFilters", () => {
  it("offers only the asset types it is given", () => {
    const filters = buildAppSecFilters({
      workspace,
      applications: [],
      targets: [],
      targetTypes: ["sast"],
    });
    const assetTypes = filters.find(
      (filter) => filter.key === APPSEC_FINDING_PARAM.ASSET_TYPE,
    );
    expect(assetTypes?.options.map((option) => option.value)).toEqual(["sast"]);
  });

  it("drops the dropdowns that have nothing to offer", () => {
    const filters = buildAppSecFilters({
      workspace,
      applications: [],
      targets: [],
      targetTypes: [],
    });
    expect(keys(filters)).not.toContain(APPSEC_FINDING_PARAM.ASSET_TYPE);
    expect(keys(filters)).not.toContain(APPSEC_FINDING_PARAM.TARGET);
    expect(keys(filters)).not.toContain(APPSEC_FINDING_PARAM.APPLICATION);
  });

  it("offers every asset type when none are given", () => {
    const filters = buildAppSecFilters({
      workspace,
      applications: [],
      targets: [],
    });
    const assetTypes = filters.find(
      (filter) => filter.key === APPSEC_FINDING_PARAM.ASSET_TYPE,
    );
    expect(assetTypes?.options.length).toBeGreaterThan(1);
  });
});
