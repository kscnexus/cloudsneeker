"use client";

import {
  ALERT_AREA_OPTIONS,
  DEFAULT_ALERT_AREAS,
  isFindingArea,
} from "@/cloudsneeker/lib/alert-areas";
import type { FindingArea } from "@/cloudsneeker/types/area-findings";
import { Field, FieldLabel } from "@/components/shadcn";
import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  MultiSelectSelectAll,
  MultiSelectSeparator,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";

interface AlertAreaFieldProps {
  values: string[];
  onValuesChange: (values: FindingArea[]) => void;
}

/** Modules (product areas) whose findings an alert rule watches. */
export const AlertAreaField = ({
  values,
  onValuesChange,
}: AlertAreaFieldProps) => {
  const selected = values.filter(isFindingArea);
  return (
    <Field>
      <FieldLabel htmlFor="alert-areas">Modules</FieldLabel>
      <MultiSelect
        values={selected}
        onValuesChange={(next) => onValuesChange(next.filter(isFindingArea))}
      >
        <MultiSelectTrigger id="alert-areas" aria-label="Modules">
          <MultiSelectValue placeholder="Cloud Security and Application Security" />
        </MultiSelectTrigger>
        <MultiSelectContent search={false}>
          <MultiSelectSelectAll
            mode="select"
            values={ALERT_AREA_OPTIONS.map((option) => option.value)}
          >
            Select all modules
          </MultiSelectSelectAll>
          <MultiSelectSeparator />
          {ALERT_AREA_OPTIONS.map((option) => (
            <MultiSelectItem key={option.value} value={option.value}>
              {option.label}
            </MultiSelectItem>
          ))}
        </MultiSelectContent>
      </MultiSelect>
      <p className="text-text-neutral-secondary text-xs">
        {selected.length === 0
          ? `No module selected: the rule watches ${DEFAULT_ALERT_AREAS.length} modules (Cloud Security and Application Security).`
          : "Governance findings are policy matches; resource filters below apply to cloud and application findings."}
      </p>
    </Field>
  );
};
