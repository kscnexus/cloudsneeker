"use client";

// Sources picker shared by the Generate dialog, the schedule form, and the
// assessment wizard. It lists only the sources the chosen report reads,
// grouped, with a search box when the list is long.

import { useState } from "react";

import {
  groupReportSources,
  matchesSourceQuery,
  type ReportSource,
  SOURCE_SEARCH_THRESHOLD,
  sourceScopeNote,
  sourcesForReport,
} from "@/cloudsneeker/lib/report-sources";
import {
  FORM_CHECK_CLASS,
  FORM_CHOICE_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import { Button, Input } from "@/components/shadcn";
import { getProviderDisplayName } from "@/types/providers";

interface ReportSourcePickerProps {
  reportType: string;
  complianceId?: string | null;
  sources: ReportSource[];
  selected: string[];
  onToggle: (id: string) => void;
  onClear: () => void;
  idPrefix: string;
}

export const ReportSourcePicker = ({
  reportType,
  complianceId,
  sources,
  selected,
  onToggle,
  onClear,
  idPrefix,
}: ReportSourcePickerProps) => {
  const [query, setQuery] = useState("");
  const applicable = sourcesForReport(reportType, sources, complianceId);
  const applicableIds = new Set(applicable.map((source) => source.id));
  const known = new Set(sources.map((source) => source.id));
  const chosen = selected.filter((id) => applicableIds.has(id));
  const leftOut = selected.filter(
    (id) => known.has(id) && !applicableIds.has(id),
  ).length;
  const groups = groupReportSources(reportType, sources, complianceId)
    .map((group) => ({
      ...group,
      sources: group.sources.filter((source) =>
        matchesSourceQuery(source, query),
      ),
    }))
    .filter((group) => group.sources.length > 0);
  const note = sourceScopeNote(reportType, complianceId);
  const searchId = `${idPrefix}-source-search`;

  return (
    <fieldset className="flex flex-col gap-2">
      <legend className="text-text-neutral-primary mb-1 text-sm font-medium">
        Sources
      </legend>
      {note ? (
        <p className="text-text-neutral-secondary text-xs">{note}</p>
      ) : null}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-text-neutral-secondary text-xs">
          {chosen.length === 0
            ? `All ${applicable.length} relevant source(s) you can see are included.`
            : `${chosen.length} of ${applicable.length} selected.`}
        </p>
        {chosen.length > 0 ? (
          <Button type="button" variant="ghost" size="sm" onClick={onClear}>
            Clear selection
          </Button>
        ) : null}
      </div>
      {leftOut > 0 ? (
        <p className="text-text-warning-primary text-xs" role="status">
          {leftOut} selected source(s) do not apply to this report and will be
          left out.
        </p>
      ) : null}
      {applicable.length > SOURCE_SEARCH_THRESHOLD ? (
        <Input
          id={searchId}
          type="search"
          aria-label="Search sources"
          placeholder="Search sources"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      ) : null}
      {applicable.length === 0 ? (
        <p className="text-text-neutral-secondary text-sm">
          No relevant source is connected. The report will show that nothing was
          assessed.
        </p>
      ) : groups.length === 0 ? (
        <p className="text-text-neutral-secondary text-sm">
          No source matches the search.
        </p>
      ) : (
        <div className="border-border-neutral-secondary flex max-h-64 flex-col gap-3 overflow-y-auto rounded-lg border p-2">
          {groups.map((group) => (
            <div
              key={group.group}
              role="group"
              aria-label={group.label}
              className="flex flex-col gap-1"
            >
              <p className="text-text-neutral-tertiary px-1 text-xs font-semibold">
                {group.label} ({group.sources.length})
              </p>
              <div className="grid gap-1 sm:grid-cols-2">
                {group.sources.map((source) => {
                  const id = `${idPrefix}-provider-${source.id}`;
                  return (
                    <label
                      key={source.id}
                      htmlFor={id}
                      className={FORM_CHOICE_CLASS}
                    >
                      <input
                        id={id}
                        type="checkbox"
                        className={FORM_CHECK_CLASS}
                        checked={selected.includes(source.id)}
                        onChange={() => onToggle(source.id)}
                      />
                      <span className="min-w-0 truncate">
                        {source.label}
                        <span className="text-text-neutral-tertiary">
                          {" "}
                          · {getProviderDisplayName(source.providerType)}
                        </span>
                      </span>
                    </label>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </fieldset>
  );
};
