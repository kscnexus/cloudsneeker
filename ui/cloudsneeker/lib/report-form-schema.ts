import { z } from "zod";

import {
  DEFAULT_REPORT_CADENCE,
  REPORT_SCHEDULE_PRESET,
  reportCadenceFromCron,
  reportCronFromCadence,
} from "@/cloudsneeker/lib/report-schedule";
import {
  REPORT_FORMAT,
  REPORT_RESOURCE_TYPE,
  REPORT_SEVERITY_ORDER,
  REPORT_TYPE_ID,
  SELECTABLE_REPORT_FORMATS,
  type ReportParams,
  type ReportScheduleResource,
  type ReportSeverity,
  type SelectableReportFormat,
} from "@/cloudsneeker/types/reports";

const ISO_DAY = /^\d{4}-\d{2}-\d{2}$/;
const FIVE_FIELD_CRON = /^\S+(\s+\S+){4}$/;

/** Share link lifetimes offered in the UI (hours; API max is 30 days). */
export const SHARE_LINK_EXPIRY_OPTIONS = [
  { hours: 24, label: "24 hours" },
  { hours: 72, label: "3 days" },
  { hours: 168, label: "7 days" },
  { hours: 720, label: "30 days" },
] as const;

export const DEFAULT_SHARE_LINK_HOURS = 72;

const severityFloorSchema = z
  .union([z.literal(""), z.enum(REPORT_SEVERITY_ORDER)])
  .default("");

const optionalDay = z
  .string()
  .trim()
  .default("")
  .refine((value) => value === "" || ISO_DAY.test(value), {
    message: "Use a date in YYYY-MM-DD format.",
  });

const reportParamsShape = {
  reportType: z.string().trim().min(1, "Choose a report."),
  providerIds: z.array(z.uuid()).default([]),
  dateFrom: optionalDay,
  dateTo: optionalDay,
  severityFloor: severityFloorSchema,
  complianceId: z.string().trim().default(""),
  formats: z
    .array(z.enum(SELECTABLE_REPORT_FORMATS))
    .min(1, "Pick at least one format."),
};

interface ParamsValues {
  reportType: string;
  dateFrom: string;
  dateTo: string;
  complianceId: string;
}

const refineParams = (values: ParamsValues, ctx: z.RefinementCtx) => {
  if (
    values.reportType === REPORT_TYPE_ID.COMPLIANCE &&
    !values.complianceId.trim()
  ) {
    ctx.addIssue({
      code: "custom",
      path: ["complianceId"],
      message: "Choose a compliance framework.",
    });
  }
  if (values.dateFrom && values.dateTo && values.dateFrom > values.dateTo) {
    ctx.addIssue({
      code: "custom",
      path: ["dateTo"],
      message: "The end date must be on or after the start date.",
    });
  }
};

export const reportGenerateFormSchema = z
  .object(reportParamsShape)
  .superRefine(refineParams);

export type ReportGenerateFormInput = z.input<typeof reportGenerateFormSchema>;
export type ReportGenerateFormValues = z.output<
  typeof reportGenerateFormSchema
>;

export const parseRecipients = (value: string): string[] =>
  Array.from(
    new Set(
      value
        .split(/[\s,;]+/)
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean),
    ),
  );

export const reportScheduleFormSchema = z
  .object({
    ...reportParamsShape,
    name: z.string().trim().min(3).max(100),
    schedulePreset: z
      .enum([
        REPORT_SCHEDULE_PRESET.DAILY,
        REPORT_SCHEDULE_PRESET.WEEKLY,
        REPORT_SCHEDULE_PRESET.MONTHLY,
        REPORT_SCHEDULE_PRESET.CUSTOM,
      ])
      .default(REPORT_SCHEDULE_PRESET.WEEKLY),
    scheduleHour: z.coerce.number().int().min(0).max(23).default(8),
    scheduleWeekday: z.coerce.number().int().min(0).max(6).default(1),
    scheduleDayOfMonth: z.coerce.number().int().min(1).max(28).default(1),
    scheduleCron: z.string().default(""),
    scheduleTimezone: z.string().trim().min(1).default("UTC"),
    recipients: z.string().default(""),
    enabled: z.boolean().default(true),
  })
  .superRefine((values, ctx) => {
    refineParams(values, ctx);
    if (
      values.schedulePreset === REPORT_SCHEDULE_PRESET.CUSTOM &&
      !FIVE_FIELD_CRON.test(values.scheduleCron.trim())
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["scheduleCron"],
        message: "Enter five cron fields: minute hour day month weekday.",
      });
    }
    const emails = parseRecipients(values.recipients);
    if (emails.length === 0) {
      ctx.addIssue({
        code: "custom",
        path: ["recipients"],
        message: "Add at least one recipient.",
      });
    }
    if (emails.length > 50) {
      ctx.addIssue({
        code: "custom",
        path: ["recipients"],
        message: "At most 50 recipients are allowed.",
      });
    }
    const invalid = emails.filter((email) => !z.email().safeParse(email).success);
    if (invalid.length > 0) {
      ctx.addIssue({
        code: "custom",
        path: ["recipients"],
        message: `Not an email address: ${invalid.join(", ")}`,
      });
    }
  });

export type ReportScheduleFormInput = z.input<typeof reportScheduleFormSchema>;
export type ReportScheduleFormValues = z.output<
  typeof reportScheduleFormSchema
>;

// Payloads sent by the server actions.

export interface ReportRunPayload {
  reportType: string;
  params: ReportParams;
  formats: SelectableReportFormat[];
}

export interface ReportSchedulePayload extends ReportRunPayload {
  name: string;
  scheduleCron: string;
  scheduleTimezone: string;
  recipients: string[];
  enabled: boolean;
}

type ParamsSource = Pick<
  ReportGenerateFormValues,
  | "reportType"
  | "providerIds"
  | "dateFrom"
  | "dateTo"
  | "severityFloor"
  | "complianceId"
>;

/** API `params` for a report: only keys the report type accepts. */
export const buildReportParams = (values: ParamsSource): ReportParams => {
  const params: ReportParams = { provider_ids: values.providerIds };
  if (values.dateFrom) params.date_from = values.dateFrom;
  if (values.dateTo) params.date_to = values.dateTo;
  if (values.severityFloor) {
    params.severity_floor = values.severityFloor as ReportSeverity;
  }
  if (values.reportType === REPORT_TYPE_ID.COMPLIANCE) {
    params.compliance_id = values.complianceId;
  }
  return params;
};

export const reportRunPayloadFromForm = (
  values: ReportGenerateFormValues,
): ReportRunPayload => ({
  reportType: values.reportType,
  params: buildReportParams(values),
  formats: values.formats,
});

export const reportSchedulePayloadFromForm = (
  values: ReportScheduleFormValues,
): ReportSchedulePayload => ({
  reportType: values.reportType,
  params: buildReportParams(values),
  formats: values.formats,
  name: values.name,
  scheduleCron: reportCronFromCadence({
    preset: values.schedulePreset,
    hour: values.scheduleHour,
    weekday: values.scheduleWeekday,
    dayOfMonth: values.scheduleDayOfMonth,
    customCron: values.scheduleCron,
  }),
  scheduleTimezone: values.scheduleTimezone,
  recipients: parseRecipients(values.recipients),
  enabled: values.enabled,
});

export const buildReportRunEnvelope = (payload: ReportRunPayload) => ({
  data: {
    type: REPORT_RESOURCE_TYPE.REPORT_RUNS,
    attributes: {
      report_type: payload.reportType,
      params: payload.params,
      formats: payload.formats,
    },
  },
});

export const buildReportScheduleEnvelope = (
  payload: ReportSchedulePayload,
  scheduleId?: string,
) => ({
  data: {
    type: REPORT_RESOURCE_TYPE.REPORT_SCHEDULES,
    ...(scheduleId ? { id: scheduleId } : {}),
    attributes: {
      name: payload.name,
      report_type: payload.reportType,
      params: payload.params,
      formats: payload.formats,
      schedule_cron: payload.scheduleCron,
      schedule_timezone: payload.scheduleTimezone,
      recipients: payload.recipients,
      enabled: payload.enabled,
    },
  },
});

export const buildScheduleToggleEnvelope = (
  scheduleId: string,
  enabled: boolean,
) => ({
  data: {
    type: REPORT_RESOURCE_TYPE.REPORT_SCHEDULES,
    id: scheduleId,
    attributes: { enabled },
  },
});

export const buildShareLinkEnvelope = (expiresInHours: number) => ({
  data: {
    type: REPORT_RESOURCE_TYPE.REPORT_SHARE_LINKS,
    attributes: { expires_in_hours: expiresInHours },
  },
});

const isSelectableFormat = (value: string): value is SelectableReportFormat =>
  (SELECTABLE_REPORT_FORMATS as readonly string[]).includes(value);

/** `2026-10-01T00:00:00+00:00` -> `2026-10-01` for date inputs. */
const toDayInput = (value: string | null | undefined): string =>
  value ? value.slice(0, 10) : "";

export const defaultScheduleFormInput = (
  reportType: string,
): ReportScheduleFormInput => ({
  name: "",
  reportType,
  providerIds: [],
  dateFrom: "",
  dateTo: "",
  severityFloor: "",
  complianceId: "",
  formats: [REPORT_FORMAT.PDF],
  schedulePreset: DEFAULT_REPORT_CADENCE.preset,
  scheduleHour: DEFAULT_REPORT_CADENCE.hour,
  scheduleWeekday: DEFAULT_REPORT_CADENCE.weekday,
  scheduleDayOfMonth: DEFAULT_REPORT_CADENCE.dayOfMonth,
  scheduleCron: "",
  scheduleTimezone: "UTC",
  recipients: "",
  enabled: true,
});

export const scheduleFormInputFromResource = (
  schedule: ReportScheduleResource,
): ReportScheduleFormInput => {
  const { attributes } = schedule;
  const cadence = reportCadenceFromCron(attributes.schedule_cron ?? "");
  const formats = (attributes.formats ?? []).filter(isSelectableFormat);
  return {
    name: attributes.name,
    reportType: attributes.report_type,
    providerIds: attributes.params?.provider_ids ?? [],
    dateFrom: toDayInput(attributes.params?.date_from),
    dateTo: toDayInput(attributes.params?.date_to),
    severityFloor: attributes.params?.severity_floor ?? "",
    complianceId: attributes.params?.compliance_id ?? "",
    formats: formats.length > 0 ? formats : [REPORT_FORMAT.PDF],
    schedulePreset: cadence.preset,
    scheduleHour: cadence.hour,
    scheduleWeekday: cadence.weekday,
    scheduleDayOfMonth: cadence.dayOfMonth,
    scheduleCron: cadence.customCron,
    scheduleTimezone: attributes.schedule_timezone || "UTC",
    recipients: (attributes.recipients ?? []).join(", "),
    enabled: attributes.enabled,
  };
};
