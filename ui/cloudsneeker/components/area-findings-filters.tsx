import {
  AREA_MUTED_INCLUDE,
  AREA_PARAM,
  AREA_SEVERITIES,
} from "@/cloudsneeker/lib/area-findings";
import {
  TRIAGE_STATUS_FILTERS,
  triageStatusLabel,
} from "@/cloudsneeker/lib/finding-triage";
import { severityLabel } from "@/cloudsneeker/lib/report-view";
import type {
  AreaFindingFacets,
  AreaFindingSource,
  FindingArea,
} from "@/cloudsneeker/types/area-findings";

import { StandardFilters } from "./standard/standard-filters";
import type { StandardFilter } from "./standard/standard-filters.utils";

interface AreaFindingsFiltersProps {
  area: FindingArea;
  sources: AreaFindingSource[];
  /** Plural label of the area's sources, e.g. "Policies". */
  sourceLabel: string;
  /** Governance: accounts, regions and resource types to offer. */
  facets?: AreaFindingFacets;
}

/** The area's filters as Cloud Security Findings shows them: searchable
 * multi-selects, applied together, with chips and Clear Filters. */
export const buildAreaFilters = ({
  sources,
  sourceLabel,
  facets,
}: Omit<AreaFindingsFiltersProps, "area">): StandardFilter[] => {
  const filters: StandardFilter[] = [
    {
      key: AREA_PARAM.SEVERITY,
      label: "Severities",
      options: AREA_SEVERITIES.map((severity) => ({
        value: severity,
        label: severityLabel(severity),
      })),
    },
    {
      key: AREA_PARAM.TRIAGE,
      label: "Statuses",
      options: TRIAGE_STATUS_FILTERS.map((status) => ({
        value: status,
        label: triageStatusLabel(status),
      })),
    },
    {
      key: AREA_PARAM.SOURCE,
      label: sourceLabel,
      wide: true,
      options: sources.map((source) => ({
        value: source.id,
        label: source.name,
      })),
    },
  ];
  if (facets && facets.accounts.length > 0) {
    filters.push({
      key: AREA_PARAM.ACCOUNT,
      label: "Accounts",
      options: facets.accounts.map((account) => ({
        value: account.id,
        label: account.name,
      })),
    });
  }
  if (facets && facets.regions.length > 0) {
    filters.push({
      key: AREA_PARAM.REGION,
      label: "Regions",
      options: facets.regions.map((region) => ({
        value: region,
        label: region,
      })),
    });
  }
  if (facets && facets.resource_types.length > 0) {
    filters.push({
      key: AREA_PARAM.RESOURCE_TYPE,
      label: "Resource Types",
      wide: true,
      options: facets.resource_types.map((type) => ({
        value: type,
        label: type,
      })),
    });
  }
  filters.push({
    key: AREA_PARAM.MUTED,
    label: "Findings (muted hidden)",
    single: true,
    options: [{ value: AREA_MUTED_INCLUDE, label: "Include muted findings" }],
  });
  return filters;
};

export const AreaFindingsFilters = ({
  area,
  ...props
}: AreaFindingsFiltersProps) => (
  <StandardFilters
    testIdPrefix={`${area}-findings`}
    filters={buildAreaFilters(props)}
  />
);
