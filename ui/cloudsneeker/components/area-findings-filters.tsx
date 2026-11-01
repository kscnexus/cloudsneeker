import Link from "next/link";

import {
  AREA_FINDING_SORT,
  AREA_FINDING_SORT_LABEL,
  AREA_PARAM,
  AREA_SEVERITIES,
  type AreaFindingFilters,
  areaFindingsPageHref,
  toggleSeverity,
} from "@/cloudsneeker/lib/area-findings";
import {
  TRIAGE_STATUS_FILTERS,
  triageStatusLabel,
} from "@/cloudsneeker/lib/finding-triage";
import { severityLabel } from "@/cloudsneeker/lib/report-view";
import { FORM_SELECT_CLASS } from "@/cloudsneeker/lib/ui-classes";
import type {
  AreaFindingSource,
  FindingArea,
} from "@/cloudsneeker/types/area-findings";
import { Button, Input } from "@/components/shadcn";
import { cn } from "@/lib/utils";

interface AreaFindingsFiltersProps {
  area: FindingArea;
  filters: AreaFindingFilters;
  sources: AreaFindingSource[];
  sourceLabel: string;
}

const chipClass = (active: boolean) =>
  cn(
    "rounded-full border px-3 py-1 text-xs font-medium transition-colors",
    active
      ? "border-button-primary bg-button-primary text-black"
      : "border-border-neutral-secondary text-text-neutral-secondary hover:text-text-neutral-primary",
  );

/** Severity and triage chips (links) plus a search, source and sort form. */
export const AreaFindingsFilters = ({
  area,
  filters,
  sources,
  sourceLabel,
}: AreaFindingsFiltersProps) => {
  const reset = { ...filters, page: 1 };
  return (
    <div className="flex flex-col gap-3">
      <nav aria-label="Severity" className="flex flex-wrap gap-2">
        {AREA_SEVERITIES.map((severity) => {
          const active = filters.severities.includes(severity);
          return (
            <Link
              key={severity}
              href={areaFindingsPageHref(area, {
                ...reset,
                severities: toggleSeverity(filters.severities, severity),
              })}
              aria-current={active ? "true" : undefined}
              className={chipClass(active)}
            >
              {severityLabel(severity)}
            </Link>
          );
        })}
      </nav>
      <nav aria-label="Triage status" className="flex flex-wrap gap-2">
        {[null, ...TRIAGE_STATUS_FILTERS].map((status) => (
          <Link
            key={status ?? "all"}
            href={areaFindingsPageHref(area, { ...reset, triage: status })}
            aria-current={status === filters.triage ? "page" : undefined}
            className={chipClass(status === filters.triage)}
          >
            {status ? triageStatusLabel(status) : "Any status"}
          </Link>
        ))}
      </nav>
      <form method="get" className="flex flex-wrap items-end gap-2">
        {filters.severities.length ? (
          <input
            type="hidden"
            name={AREA_PARAM.SEVERITY}
            value={filters.severities.join(",")}
          />
        ) : null}
        {filters.triage ? (
          <input
            type="hidden"
            name={AREA_PARAM.TRIAGE}
            value={filters.triage}
          />
        ) : null}
        <label className="flex min-w-48 flex-1 flex-col gap-1 text-xs">
          <span className="text-text-neutral-secondary font-semibold">
            Search
          </span>
          <Input
            name={AREA_PARAM.SEARCH}
            defaultValue={filters.search}
            placeholder="Rule, title or resource"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="text-text-neutral-secondary font-semibold">
            {sourceLabel}
          </span>
          <select
            name={AREA_PARAM.SOURCE}
            defaultValue={filters.source ?? ""}
            className={cn(FORM_SELECT_CLASS, "w-48")}
          >
            <option value="">All</option>
            {sources.map((source) => (
              <option key={source.id} value={source.id}>
                {source.name}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="text-text-neutral-secondary font-semibold">
            Sort by
          </span>
          <select
            name={AREA_PARAM.SORT}
            defaultValue={filters.sort}
            className={cn(FORM_SELECT_CLASS, "w-40")}
          >
            {Object.values(AREA_FINDING_SORT).map((sort) => (
              <option key={sort} value={sort}>
                {AREA_FINDING_SORT_LABEL[sort]}
              </option>
            ))}
          </select>
        </label>
        <Button type="submit" size="sm">
          Apply
        </Button>
        <Button asChild size="sm" variant="ghost">
          <Link href={areaFindingsPageHref(area, {})}>Reset</Link>
        </Button>
      </form>
    </div>
  );
};
