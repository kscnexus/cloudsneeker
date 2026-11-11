import Link from "next/link";

import { APPSEC_SEGMENT, appSecFindingsHref } from "@/cloudsneeker/lib/appsec";
import { FORM_SELECT_CLASS } from "@/cloudsneeker/lib/ui-classes";
import type {
  AppSecComponentAttributes,
  AppSecResource,
} from "@/cloudsneeker/types/appsec";
import { Button, Input } from "@/components/shadcn";
import { cn } from "@/lib/utils";

import {
  AppSecSeverityBadge,
  ChipLink,
  ROW_LINK_CLASS,
  TABLE_CLASS,
  TABLE_WRAPPER_CLASS,
  TD_CLASS,
  TD_PRIMARY_CLASS,
  TH_CLASS,
} from "./appsec-ui";

export const COMPONENT_PARAM = {
  SEARCH: "q",
  ECOSYSTEM: "ecosystem",
  RELATIONSHIP: "relationship",
  VULNERABLE: "vulnerable",
  UNLICENSED: "unlicensed",
  LICENSE: "license",
  SORT: "sort",
  PAGE: "page",
} as const;

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

const SORTS: Record<string, string> = {
  "-vulnerability_count": "Most vulnerabilities",
  name: "Name",
  ecosystem: "Ecosystem",
  relationship: "Relationship",
};

const one = (value: string | string[] | undefined): string =>
  ((Array.isArray(value) ? value[0] : value) ?? "").trim();

export const parseComponentFilters = (
  params: Record<string, string | string[] | undefined>,
): ComponentFilters => {
  const sort = one(params[COMPONENT_PARAM.SORT]);
  return {
    search: one(params[COMPONENT_PARAM.SEARCH]),
    ecosystem: one(params[COMPONENT_PARAM.ECOSYSTEM]),
    relationship: one(params[COMPONENT_PARAM.RELATIONSHIP]),
    vulnerable: one(params[COMPONENT_PARAM.VULNERABLE]) === "1",
    unlicensed: one(params[COMPONENT_PARAM.UNLICENSED]) === "1",
    license: one(params[COMPONENT_PARAM.LICENSE]),
    sort: sort in SORTS ? sort : "-vulnerability_count",
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
  if (filters.vulnerable) query.set(COMPONENT_PARAM.VULNERABLE, "1");
  if (filters.unlicensed) query.set(COMPONENT_PARAM.UNLICENSED, "1");
  if (filters.license) query.set(COMPONENT_PARAM.LICENSE, filters.license);
  if (filters.sort && filters.sort !== "-vulnerability_count")
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

interface ComponentFiltersBarProps {
  base: string;
  filters: ComponentFilters;
  ecosystems: string[];
  /** Query parameters to keep (target, application). */
  extra?: Record<string, string>;
}

export const ComponentFiltersBar = ({
  base,
  filters,
  ecosystems,
  extra = {},
}: ComponentFiltersBarProps) => {
  const reset = { ...filters, page: 1 };
  return (
    <div className="flex flex-col gap-3">
      <nav aria-label="Component filters" className="flex flex-wrap gap-2">
        <ChipLink
          href={componentsHref(
            base,
            { ...reset, vulnerable: !filters.vulnerable },
            extra,
          )}
          active={filters.vulnerable}
        >
          Vulnerable
        </ChipLink>
        {(["direct", "indirect"] as const).map((relationship) => (
          <ChipLink
            key={relationship}
            href={componentsHref(
              base,
              {
                ...reset,
                relationship:
                  filters.relationship === relationship ? "" : relationship,
              },
              extra,
            )}
            active={filters.relationship === relationship}
          >
            {relationship === "direct" ? "Direct" : "Transitive"}
          </ChipLink>
        ))}
        <ChipLink
          href={componentsHref(
            base,
            { ...reset, unlicensed: !filters.unlicensed },
            extra,
          )}
          active={filters.unlicensed}
        >
          No license stated
        </ChipLink>
        {filters.license ? (
          <ChipLink
            href={componentsHref(base, { ...reset, license: "" }, extra)}
            active
          >
            License: {filters.license} ×
          </ChipLink>
        ) : null}
      </nav>
      <form method="get" className="flex flex-wrap items-end gap-2">
        {Object.entries({
          ...extra,
          ...(filters.vulnerable ? { [COMPONENT_PARAM.VULNERABLE]: "1" } : {}),
          ...(filters.unlicensed ? { [COMPONENT_PARAM.UNLICENSED]: "1" } : {}),
          ...(filters.relationship
            ? { [COMPONENT_PARAM.RELATIONSHIP]: filters.relationship }
            : {}),
          ...(filters.license
            ? { [COMPONENT_PARAM.LICENSE]: filters.license }
            : {}),
        }).map(([name, value]) => (
          <input key={name} type="hidden" name={name} value={value} />
        ))}
        <label className="flex min-w-48 flex-1 flex-col gap-1 text-xs">
          <span className="text-text-neutral-secondary font-semibold">
            Search
          </span>
          <Input
            name={COMPONENT_PARAM.SEARCH}
            defaultValue={filters.search}
            placeholder="Package name or package URL"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="text-text-neutral-secondary font-semibold">
            Ecosystem
          </span>
          <select
            name={COMPONENT_PARAM.ECOSYSTEM}
            defaultValue={filters.ecosystem}
            className={cn(FORM_SELECT_CLASS, "w-40")}
          >
            <option value="">All</option>
            {ecosystems.map((ecosystem) => (
              <option key={ecosystem} value={ecosystem}>
                {ecosystem}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="text-text-neutral-secondary font-semibold">
            Sort by
          </span>
          <select
            name={COMPONENT_PARAM.SORT}
            defaultValue={filters.sort}
            className={cn(FORM_SELECT_CLASS, "w-48")}
          >
            {Object.entries(SORTS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <Button type="submit" size="sm">
          Apply
        </Button>
        <Button asChild size="sm" variant="ghost">
          <Link href={componentsHref(base, {}, extra)}>Reset</Link>
        </Button>
      </form>
    </div>
  );
};

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
