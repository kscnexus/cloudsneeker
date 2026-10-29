"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
import { useForm, useWatch } from "react-hook-form";

import {
  createReportSchedule,
  updateReportSchedule,
} from "@/cloudsneeker/actions/reports";
import {
  FormActions,
  FormAlert,
  FormField,
} from "@/cloudsneeker/components/form-layout";
import { SectionCard } from "@/cloudsneeker/components/section-card";
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
import {
  FORM_CHECK_CLASS,
  FORM_CHOICE_CLASS,
  FORM_SELECT_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import { Button, Input, Textarea } from "@/components/shadcn";

import {
  asReportParamsForm,
  ReportParamsFields,
  type ReportOption,
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
    <form onSubmit={onSubmit} className="flex min-w-0 flex-col gap-5">
      <SectionCard title="Report" description="What the scheduled run builds.">
        <FormField
          id="report-schedule-name"
          label="Name"
          error={errors.name?.message}
        >
          <Input
            id="report-schedule-name"
            placeholder="Weekly executive summary"
            {...form.register("name")}
          />
        </FormField>

        <FormField
          id="report-schedule-type"
          label="Report"
          error={errors.reportType?.message}
        >
          <select
            id="report-schedule-type"
            className={FORM_SELECT_CLASS}
            {...form.register("reportType")}
          >
            {catalog.map((entry) => (
              <option key={entry.id} value={entry.id}>
                {entry.title}
              </option>
            ))}
          </select>
        </FormField>

        <ReportParamsFields
          form={asReportParamsForm(form)}
          idPrefix="report-schedule"
          providers={providers}
          frameworks={frameworks}
        />
      </SectionCard>

      <SectionCard
        title="Delivery"
        description="When the report runs and who receives it."
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <FormField id="report-schedule-preset" label="Cadence">
            <select
              id="report-schedule-preset"
              className={FORM_SELECT_CLASS}
              {...form.register("schedulePreset")}
            >
              {REPORT_SCHEDULE_PRESET_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </FormField>
          {preset !== REPORT_SCHEDULE_PRESET.CUSTOM ? (
            <FormField
              id="report-schedule-hour"
              label="Hour (0–23)"
              error={errors.scheduleHour?.message}
            >
              <Input
                id="report-schedule-hour"
                type="number"
                min={0}
                max={23}
                {...form.register("scheduleHour")}
              />
            </FormField>
          ) : null}
          {preset === REPORT_SCHEDULE_PRESET.WEEKLY ? (
            <FormField id="report-schedule-weekday" label="Day of week">
              <select
                id="report-schedule-weekday"
                className={FORM_SELECT_CLASS}
                {...form.register("scheduleWeekday")}
              >
                {WEEKDAY_OPTIONS.map((day) => (
                  <option key={day.value} value={day.value}>
                    {day.label}
                  </option>
                ))}
              </select>
            </FormField>
          ) : null}
          {preset === REPORT_SCHEDULE_PRESET.MONTHLY ? (
            <FormField
              id="report-schedule-day"
              label="Day of month (1–28)"
              error={errors.scheduleDayOfMonth?.message}
            >
              <Input
                id="report-schedule-day"
                type="number"
                min={1}
                max={28}
                {...form.register("scheduleDayOfMonth")}
              />
            </FormField>
          ) : null}
          {preset === REPORT_SCHEDULE_PRESET.CUSTOM ? (
            <FormField
              id="report-schedule-cron"
              label="Cron"
              help="Five fields: minute hour day month weekday."
              error={errors.scheduleCron?.message}
            >
              <Input
                id="report-schedule-cron"
                className="font-mono text-sm"
                placeholder="0 8 * * 1-5"
                {...form.register("scheduleCron")}
              />
            </FormField>
          ) : null}
          <FormField
            id="report-schedule-timezone"
            label="Timezone"
            error={errors.scheduleTimezone?.message}
          >
            <Input
              id="report-schedule-timezone"
              placeholder="UTC"
              {...form.register("scheduleTimezone")}
            />
          </FormField>
        </div>

        <FormField
          id="report-schedule-recipients"
          label="Recipients"
          help="Separate addresses with commas or new lines. Large reports are sent as a secure link instead of an attachment."
          error={errors.recipients?.message}
        >
          <Textarea
            id="report-schedule-recipients"
            rows={3}
            placeholder="ciso@example.com, security@example.com"
            {...form.register("recipients")}
          />
        </FormField>

        <label htmlFor="report-schedule-enabled" className={FORM_CHOICE_CLASS}>
          <input
            id="report-schedule-enabled"
            type="checkbox"
            className={FORM_CHECK_CLASS}
            {...form.register("enabled")}
          />
          Enabled
        </label>
      </SectionCard>

      <FormAlert message={error} />

      <FormActions>
        <Button type="button" variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={saving}>
          {saving
            ? "Saving…"
            : scheduleId
              ? "Save schedule"
              : "Create schedule"}
        </Button>
      </FormActions>
    </form>
  );
};
