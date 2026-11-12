import Link from "next/link";

import { APPSEC_SEGMENT, appSecFindingsHref } from "@/cloudsneeker/lib/appsec";
import type {
  AppSecComponentAttributes,
  AppSecResource,
} from "@/cloudsneeker/types/appsec";
import { DataTableSearch } from "@/components/shadcn/table/data-table-search";
import { cn } from "@/lib/utils";

import {
  AppSecSeverityBadge,
  ROW_LINK_CLASS,
  TABLE_CLASS,
  TABLE_WRAPPER_CLASS,
  TD_CLASS,
  TD_PRIMARY_CLASS,
  TH_CLASS,
} from "./appsec-ui";
import { SortSelect } from "./standard/sort-select";
import { StandardFilters } from "./standard/standard-filters";
import type { StandardFilter } from "./standard/standard-filters.utils";

export const COMPONENT_PARAM = {
  SEARCH: "filter[search]",
  ECOSYSTEM: "filter[ecosystem]",
  RELATIONSHIP: "filter[relationship]",
  VULNERABLE: "filter[vulnerable]",
  UNLICENSED: "filter[unlicensed]",
  LICENSE: "filter[license]",
  SORT: "sort",
  PAGE: "page",
} as const;

/** Names used before the standard filter bar; still read for old links. */
const LEGACY_COMPONENT_PARAM: Record<string, string> = {
  [COMPONENT_PARAM.SEARCH]: "q",
  [COMPONENT_PARAM.ECOSYSTEM]: "ecosystem",
  [COMPONENT_PARAM.RELATIONSHIP]: "relationship",
  [COMPONENT_PARAM.VULNERABLE]: "vulnerable",
  [COMPONENT_PARAM.UNLICENSED]: "unlicensed",
  [COMPONENT_PARAM.LICENSE]: "license",
};

export interface ComponentFilters {
  search: string;
  ecosystem: string;
  relationship: string;
  vulnerable: boolean;
  unlicensed: boolean;
  license: string;
  sort: string;
  page: number;
}

const DEFAULT_SORT = "-vulnerability_count";

const SORTS: Record<string, string> = {
  [DEFAULT_SORT]: "Most vulnerabilities",
  name: "Name",
  ecosystem: "Ecosystem",
  relationship: "Relationship",
};

const RELATIONSHIP_FILTERS = ["direct", "indirect"] as const;

const one = (value: string | string[] | undefined): string =>
  ((Array.isArray(value) ? value[0] : value) ?? "").trim();

type Params = Record<string, string | string[] | undefined>;

const read = (params: Params, name: string): string =>
  one(params[name]) ||
  (LEGACY_COMPONENT_PARAM[name]
    ? one(params[LEGACY_COMPONENT_PARAM[name]])
    : "");

const truthy = (value: string): boolean => value === "1" || value === "true";

export const parseComponentFilters = (params: Params): ComponentFilters => {
  const sort = one(params[COMPONENT_PARAM.SORT]);
  return {
    search: read(params, COMPONENT_PARAM.SEARCH),
    ecosystem: read(params, COMPONENT_PARAM.ECOSYSTEM),
    relationship: read(params, COMPONENT_PARAM.RELATIONSHIP),
    vulnerable: truthy(read(params, COMPONENT_PARAM.VULNERABLE)),
    unlicensed: truthy(read(params, COMPONENT_PARAM.UNLICENSED)),
    license: read(params, COMPONENT_PARAM.LICENSE),
    sort: sort in SORTS ? sort : DEFAULT_SORT,
    page: Math.max(
      1,
      Number.parseInt(one(params[COMPONENT_PARAM.PAGE]), 10) || 1,
    ),
  };
};

/** Page URL: `base` plus the component filters (defaults left out). */
export const componentsHref = (
  base: string,
  filters: Partial<ComponentFilters>,
  extra: Record<string, string> = {},
): string => {
  const query = new URLSearchParams(extra);
  if (filters.search) query.set(COMPONENT_PARAM.SEARCH, filters.search);
  if (filters.ecosystem)
    query.set(COMPONENT_PARAM.ECOSYSTEM, filters.ecosystem);
  if (filters.relationship)
    query.set(COMPONENT_PARAM.RELATIONSHIP, filters.relationship);
  if (filters.vulnerable) query.set(COMPONENT_PARAM.VULNERABLE, "true");
  if (filters.unlicensed) query.set(COMPONENT_PARAM.UNLICENSED, "true");
  if (filters.license) query.set(COMPONENT_PARAM.LICENSE, filters.license);
  if (filters.sort && filters.sort !== DEFAULT_SORT)
    query.set(COMPONENT_PARAM.SORT, filters.sort);
  if (filters.page && filters.page > 1)
    query.set(COMPONENT_PARAM.PAGE, String(filters.page));
  const serialized = query.toString();
  return serialized ? `${base}?${serialized}` : base;
};

/** API query for the component list endpoints. */
export const componentsQuery = (
  filters: ComponentFilters,
): Record<string, string> => {
  const query: Record<string, string> = {
    sort: filters.sort,
    "page[number]": String(filters.page),
    "page[size]": "50",
  };
  if (filters.search) query["filter[search]"] = filters.search;
  if (filters.ecosystem) query["filter[ecosystem]"] = filters.ecosystem;
  if (filters.relationship)
    query["filter[relationship]"] = filters.relationship;
  if (filters.vulnerable) query["filter[vulnerable]"] = "true";
  if (filters.unlicensed) query["filter[unlicensed]"] = "true";
  if (filters.license) query["filter[license]"] = filters.license;
  return query;
};

/** Filter bar of the component lists (Cloud Security Findings controls). */
export const buildComponentFilters = ({
  ecosystems,
  licenses = [],
}: {
  ecosystems: string[];
  licenses?: string[];
}): StandardFilter[] => [
  {
    key: COMPONENT_PARAM.ECOSYSTEM,
    label: "Ecosystems",
    single: true,
    options: ecosystems.map((ecosystem) => ({
      value: ecosystem,
      label: ecosystem || "unknown",
    })),
  },
  {
    key: COMPONENT_PARAM.RELATIONSHIP,
    label: "Relationships",
    single: true,
    options: RELATIONSHIP_FILTERS.map((relationship) => ({
      value: relationship,
      label: RELATIONSHIP_LABEL[relationship],
    })),
  },
  {
    key: COMPONENT_PARAM.VULNERABLE,
    label: "Vulnerability states",
    single: true,
    options: [{ value: "true", label: "Vulnerable" }],
  },
  {
    key: COMPONENT_PARAM.LICENSE,
    label: "Licenses",
    single: true,
    wide: true,
    options: licenses.map((license) => ({ value: license, label: license })),
  },
  {
    key: COMPONENT_PARAM.UNLICENSED,
    label: "License statements",
    single: true,
    options: [{ value: "true", label: "No license stated" }],
  },
];

interface ComponentFiltersBarProps {
  ecosystems: string[];
  licenses?: string[];
  sort: string;
}

/** Filters, search and sort above a component table. */
export const ComponentFiltersBar = ({
  ecosystems,
  licenses,
  sort,
}: ComponentFiltersBarProps) => (
  <div className="flex flex-col gap-3">
    <StandardFilters
      testIdPrefix="components"
      filters={buildComponentFilters({ ecosystems, licenses })}
      trailingControls={
        <div className="w-full md:w-80">
          <DataTableSearch placeholder="Package name or URL (press Enter)" />
        </div>
      }
    />
    <div className="flex justify-end">
      <SortSelect
        value={sort}
        defaultValue={DEFAULT_SORT}
        options={Object.entries(SORTS).map(([value, label]) => ({
          value,
          label,
        }))}
      />
    </div>
  </div>
);

const RELATIONSHIP_LABEL: Record<string, string> = {
  direct: "Direct",
  indirect: "Transitive",
  root: "Root",
  workspace: "Workspace",
  unknown: "Not stated",
};

interface ComponentsTableProps {
  components: AppSecResource<AppSecComponentAttributes>[];
  /** Show the asset column (lists that span assets). */
  showTarget?: boolean;
}

export const AppSecComponentsTable = ({
  components,
  showTarget = false,
}: ComponentsTableProps) => (
  <div className={TABLE_WRAPPER_CLASS}>
    <table className={TABLE_CLASS}>
      <thead>
        <tr>
          {[
            "Component",
            "Version",
            "Ecosystem",
            "Dependency",
            "Licenses",
            "Vulnerabilities",
            "Fixed in",
            ...(showTarget ? ["Asset"] : []),
          ].map((heading) => (
            <th key={heading} scope="col" className={TH_CLASS}>
              {heading}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {components.map(({ id, attributes }) => (
          <tr key={id}>
            <td className={cn(TD_PRIMARY_CLASS, "max-w-xs")}>
              <span className="font-medium break-all">{attributes.name}</span>
              <p className="text-text-neutral-tertiary truncate text-xs">
                {attributes.location}
                {attributes.dev ? " · development only" : ""}
              </p>
            </td>
            <td className={cn(TD_CLASS, "break-all")}>{attributes.version}</td>
            <td className={TD_CLASS}>{attributes.ecosystem}</td>
            <td className={TD_CLASS}>
              {RELATIONSHIP_LABEL[attributes.relationship] ??
                attributes.relationship}
            </td>
            <td className={cn(TD_CLASS, "max-w-48 text-xs")}>
              {attributes.licenses.length > 0
                ? attributes.licenses.join(", ")
                : "Not stated"}
            </td>
            <td className={TD_CLASS}>
              {attributes.vulnerability_count > 0 ? (
                <span className="flex items-center gap-2">
                  <Link
                    className={ROW_LINK_CLASS}
                    href={appSecFindingsHref(APPSEC_SEGMENT.VULNERABILITIES, {
                      pkg: attributes.name,
                      target: attributes.target_id,
                    })}
                  >
                    {attributes.vulnerability_count}
                  </Link>
                  <AppSecSeverityBadge severity={attributes.max_severity} />
                </span>
              ) : (
                "0"
              )}
            </td>
            <td className={cn(TD_CLASS, "break-all")}>
              {attributes.fixed_version || "–"}
            </td>
            {showTarget ? (
              <td className={cn(TD_CLASS, "max-w-40 truncate")}>
                {attributes.target_name}
              </td>
            ) : null}
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);
