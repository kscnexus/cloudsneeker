"use client";

// Filter fields shared by the Generate dialog and the schedule form.

import { type UseFormReturn, useWatch } from "react-hook-form";

import { severityLabel } from "@/cloudsneeker/lib/report-view";
import { FORM_SELECT_CLASS } from "@/cloudsneeker/lib/ui-classes";
import {
  REPORT_SEVERITY_ORDER,
  REPORT_TYPE_ID,
  SELECTABLE_REPORT_FORMATS,
  type SelectableReportFormat,
} from "@/cloudsneeker/types/reports";
import { Input, Label } from "@/components/shadcn";

export interface ReportOption {
  id: string;
  label: string;
}

export interface ReportParamsFieldValues {
  reportType: string;
  providerIds: string[];
  dateFrom: string;
  dateTo: string;
  severityFloor: string;
  complianceId: string;
  formats: SelectableReportFormat[];
}

const FORMAT_LABEL: Record<SelectableReportFormat, string> = {
  pdf: "PDF (branded document)",
  xlsx: "Excel workbook",
  csv: "CSV (detail rows)",
};

/** Kept for existing imports; the shared form select style. */
export const SELECT_CLASS = FORM_SELECT_CLASS;

const FieldError = ({ message }: { message?: string }) =>
  message ? <p className="text-text-error-primary text-xs">{message}</p> : null;

/**
 * The generate and schedule forms both contain these fields; each passes its
 * form narrowed to them (`asReportParamsForm`).
 */
export type ReportParamsForm = UseFormReturn<ReportParamsFieldValues>;

export const asReportParamsForm = (form: object): ReportParamsForm =>
  form as ReportParamsForm;

interface ReportParamsFieldsProps {
  form: ReportParamsForm;
  idPrefix: string;
  providers: ReportOption[];
  frameworks: ReportOption[];
}

export function ReportParamsFields({
  form,
  idPrefix,
  providers,
  frameworks,
}: ReportParamsFieldsProps) {
  const reportType = useWatch({ control: form.control, name: "reportType" });
  const selectedProviders: string[] =
    useWatch({ control: form.control, name: "providerIds" }) ?? [];
  const selectedFormats: string[] =
    useWatch({ control: form.control, name: "formats" }) ?? [];
  const errors = form.formState.errors;

  const toggle = (
    name: "providerIds" | "formats",
    current: string[],
    value: string,
  ) => {
    const next = current.includes(value)
      ? current.filter((item) => item !== value)
      : [...current, value];
    const options = { shouldDirty: true, shouldValidate: true } as const;
    if (name === "formats") {
      form.setValue("formats", next as SelectableReportFormat[], options);
    } else {
      form.setValue("providerIds", next, options);
    }
  };

  return (
    <>
      <fieldset className="flex flex-col gap-2">
        <legend className="text-text-neutral-primary mb-1 text-sm font-medium">
          Sources
        </legend>
        <p className="text-text-neutral-secondary text-xs">
          {selectedProviders.length === 0
            ? "All sources you can see are included."
            : `${selectedProviders.length} selected.`}
        </p>
        {providers.length > 0 ? (
          <div className="border-border-neutral-secondary flex max-h-40 flex-col gap-1 overflow-y-auto rounded-md border p-2">
            {providers.map((provider) => {
              const id = `${idPrefix}-provider-${provider.id}`;
              return (
                <label
                  key={provider.id}
                  htmlFor={id}
                  className="text-text-neutral-primary flex items-center gap-2 text-sm"
                >
                  <input
                    id={id}
                    type="checkbox"
                    className="size-4"
                    checked={selectedProviders.includes(provider.id)}
                    onChange={() =>
                      toggle("providerIds", selectedProviders, provider.id)
                    }
                  />
                  {provider.label}
                </label>
              );
            })}
          </div>
        ) : null}
      </fieldset>

      <div className="grid gap-3 sm:grid-cols-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor={`${idPrefix}-date-from`}>From</Label>
          <Input
            id={`${idPrefix}-date-from`}
            type="date"
            {...form.register("dateFrom")}
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor={`${idPrefix}-date-to`}>To</Label>
          <Input
            id={`${idPrefix}-date-to`}
            type="date"
            {...form.register("dateTo")}
          />
          <FieldError message={errors.dateTo?.message} />
        </div>
      </div>

      <div className="flex flex-col gap-1.5">
        <Label htmlFor={`${idPrefix}-severity`}>Minimum severity</Label>
        <select
          id={`${idPrefix}-severity`}
          className={SELECT_CLASS}
          {...form.register("severityFloor")}
        >
          <option value="">All severities</option>
          {REPORT_SEVERITY_ORDER.map((severity) => (
            <option key={severity} value={severity}>
              {severityLabel(severity)} and above
            </option>
          ))}
        </select>
      </div>

      {reportType === REPORT_TYPE_ID.COMPLIANCE ? (
        <div className="flex flex-col gap-1.5">
          <Label htmlFor={`${idPrefix}-framework`}>Framework</Label>
          <select
            id={`${idPrefix}-framework`}
            className={SELECT_CLASS}
            {...form.register("complianceId")}
          >
            <option value="">Choose a framework</option>
            {frameworks.map((framework) => (
              <option key={framework.id} value={framework.id}>
                {framework.label}
              </option>
            ))}
          </select>
          {frameworks.length === 0 ? (
            <p className="text-text-neutral-secondary text-xs">
              Frameworks appear after a completed cloud scan.
            </p>
          ) : null}
          <FieldError message={errors.complianceId?.message} />
        </div>
      ) : null}

      <fieldset className="flex flex-col gap-2">
        <legend className="text-text-neutral-primary mb-1 text-sm font-medium">
          Formats
        </legend>
        <div className="flex flex-wrap gap-4">
          {SELECTABLE_REPORT_FORMATS.map((format) => {
            const id = `${idPrefix}-format-${format}`;
            return (
              <label
                key={format}
                htmlFor={id}
                className="text-text-neutral-primary flex items-center gap-2 text-sm"
              >
                <input
                  id={id}
                  type="checkbox"
                  className="size-4"
                  checked={selectedFormats.includes(format)}
                  onChange={() => toggle("formats", selectedFormats, format)}
                />
                {FORMAT_LABEL[format]}
              </label>
            );
          })}
        </div>
        <p className="text-text-neutral-secondary text-xs">
          Every report can also be viewed in the browser.
        </p>
        <FieldError message={errors.formats?.message} />
      </fieldset>
    </>
  );
}
