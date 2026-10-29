"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
import { useForm, useWatch } from "react-hook-form";

import {
  createReportSchedule,
  updateReportSchedule,
} from "@/cloudsneeker/actions/reports";
import type { ReportCatalogEntry } from "@/cloudsneeker/lib/report-catalog";
import {
  reportScheduleFormSchema,
  reportSchedulePayloadFromForm,
  type ReportScheduleFormInput,
  type ReportScheduleFormValues,
} from "@/cloudsneeker/lib/report-form-schema";
import {
  REPORT_SCHEDULE_PRESET,
  REPORT_SCHEDULE_PRESET_OPTIONS,
  WEEKDAY_OPTIONS,
} from "@/cloudsneeker/lib/report-schedule";
import { Button, Input, Label, Textarea } from "@/components/shadcn";

import {
  asReportParamsForm,
  ReportParamsFields,
  type ReportOption,
  SELECT_CLASS,
} from "./report-params-fields";

interface ReportScheduleFormProps {
  catalog: ReportCatalogEntry[];
  providers: ReportOption[];
  frameworks: ReportOption[];
  initialValues: ReportScheduleFormInput;
  scheduleId?: string;
  onDone: () => void;
  onCancel: () => void;
}

export const ReportScheduleForm = ({
  catalog,
  providers,
  frameworks,
  initialValues,
  scheduleId,
  onDone,
  onCancel,
}: ReportScheduleFormProps) => {
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const form = useForm<
    ReportScheduleFormInput,
    unknown,
    ReportScheduleFormValues
  >({
    resolver: zodResolver(reportScheduleFormSchema),
    defaultValues: initialValues,
  });
  const preset = useWatch({ control: form.control, name: "schedulePreset" });
  const errors = form.formState.errors;

  const onSubmit = form.handleSubmit(async (values) => {
    setSaving(true);
    setError(null);
    const payload = reportSchedulePayloadFromForm(values);
    const result = scheduleId
      ? await updateReportSchedule(scheduleId, payload)
      : await createReportSchedule(payload);
    setSaving(false);
    if (result && "error" in result && result.error) {
      setError(
        typeof result.error === "string"
          ? result.error
          : "Could not save the schedule.",
      );
      return;
    }
    onDone();
  });

  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-4">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="report-schedule-name">Name</Label>
        <Input
          id="report-schedule-name"
          placeholder="Weekly executive summary"
          {...form.register("name")}
        />
        {errors.name ? (
          <p className="text-text-error-primary text-xs">
            {errors.name.message}
          </p>
        ) : null}
      </div>

      <div className="flex flex-col gap-1.5">
        <Label htmlFor="report-schedule-type">Report</Label>
        <select
          id="report-schedule-type"
          className={SELECT_CLASS}
          {...form.register("reportType")}
        >
          {catalog.map((entry) => (
            <option key={entry.id} value={entry.id}>
              {entry.title}
            </option>
          ))}
        </select>
      </div>

      <ReportParamsFields
        form={asReportParamsForm(form)}
        idPrefix="report-schedule"
        providers={providers}
        frameworks={frameworks}
      />

      <fieldset className="border-border-neutral-secondary flex flex-col gap-3 rounded-xl border p-4">
        <legend className="text-text-neutral-primary px-1 text-sm font-semibold">
          Delivery
        </legend>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="report-schedule-preset">Cadence</Label>
            <select
              id="report-schedule-preset"
              className={SELECT_CLASS}
              {...form.register("schedulePreset")}
            >
              {REPORT_SCHEDULE_PRESET_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
          {preset !== REPORT_SCHEDULE_PRESET.CUSTOM ? (
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="report-schedule-hour">Hour (0–23)</Label>
              <Input
                id="report-schedule-hour"
                type="number"
                min={0}
                max={23}
                {...form.register("scheduleHour")}
              />
            </div>
          ) : null}
          {preset === REPORT_SCHEDULE_PRESET.WEEKLY ? (
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="report-schedule-weekday">Day of week</Label>
              <select
                id="report-schedule-weekday"
                className={SELECT_CLASS}
                {...form.register("scheduleWeekday")}
              >
                {WEEKDAY_OPTIONS.map((day) => (
                  <option key={day.value} value={day.value}>
                    {day.label}
                  </option>
                ))}
              </select>
            </div>
          ) : null}
          {preset === REPORT_SCHEDULE_PRESET.MONTHLY ? (
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="report-schedule-day">Day of month (1–28)</Label>
              <Input
                id="report-schedule-day"
                type="number"
                min={1}
                max={28}
                {...form.register("scheduleDayOfMonth")}
              />
            </div>
          ) : null}
          {preset === REPORT_SCHEDULE_PRESET.CUSTOM ? (
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="report-schedule-cron">
                Cron (minute hour day month weekday)
              </Label>
              <Input
                id="report-schedule-cron"
                className="font-mono text-sm"
                placeholder="0 8 * * 1-5"
                {...form.register("scheduleCron")}
              />
              {errors.scheduleCron ? (
                <p className="text-text-error-primary text-xs">
                  {errors.scheduleCron.message}
                </p>
              ) : null}
            </div>
          ) : null}
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="report-schedule-timezone">Timezone</Label>
            <Input
              id="report-schedule-timezone"
              placeholder="UTC"
              {...form.register("scheduleTimezone")}
            />
          </div>
        </div>

        <div className="flex flex-col gap-1.5">
          <Label htmlFor="report-schedule-recipients">Recipients</Label>
          <Textarea
            id="report-schedule-recipients"
            rows={3}
            placeholder="ciso@example.com, security@example.com"
            {...form.register("recipients")}
          />
          <p className="text-text-neutral-secondary text-xs">
            Separate addresses with commas or new lines. Large reports are sent
            as a secure link instead of an attachment.
          </p>
          {errors.recipients ? (
            <p className="text-text-error-primary text-xs">
              {errors.recipients.message}
            </p>
          ) : null}
        </div>

        <label
          htmlFor="report-schedule-enabled"
          className="text-text-neutral-primary flex items-center gap-2 text-sm"
        >
          <input
            id="report-schedule-enabled"
            type="checkbox"
            className="size-4"
            {...form.register("enabled")}
          />
          Enabled
        </label>
      </fieldset>

      {error ? <p className="text-text-error-primary text-sm">{error}</p> : null}

      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={saving}>
          {saving ? "Saving…" : scheduleId ? "Save schedule" : "Create schedule"}
        </Button>
      </div>
    </form>
  );
};
