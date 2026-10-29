// Cadence presets for scheduled reports. Same shape as the governance
// schedule helpers (`custodian-schedule.ts`) plus a monthly preset; the API
// validates the resulting five-field cron.

export const REPORT_SCHEDULE_PRESET = {
  DAILY: "daily",
  WEEKLY: "weekly",
  MONTHLY: "monthly",
  CUSTOM: "custom",
} as const;

export type ReportSchedulePreset =
  (typeof REPORT_SCHEDULE_PRESET)[keyof typeof REPORT_SCHEDULE_PRESET];

export const REPORT_SCHEDULE_PRESET_OPTIONS = [
  { value: REPORT_SCHEDULE_PRESET.DAILY, label: "Daily" },
  { value: REPORT_SCHEDULE_PRESET.WEEKLY, label: "Weekly" },
  { value: REPORT_SCHEDULE_PRESET.MONTHLY, label: "Monthly" },
  { value: REPORT_SCHEDULE_PRESET.CUSTOM, label: "Custom cron" },
] as const;

export const WEEKDAY_OPTIONS = [
  { value: 1, label: "Monday" },
  { value: 2, label: "Tuesday" },
  { value: 3, label: "Wednesday" },
  { value: 4, label: "Thursday" },
  { value: 5, label: "Friday" },
  { value: 6, label: "Saturday" },
  { value: 0, label: "Sunday" },
] as const;

export interface ReportCadence {
  preset: ReportSchedulePreset;
  hour: number;
  weekday: number;
  dayOfMonth: number;
  customCron: string;
}

export const DEFAULT_REPORT_CADENCE: ReportCadence = {
  preset: REPORT_SCHEDULE_PRESET.WEEKLY,
  hour: 8,
  weekday: 1,
  dayOfMonth: 1,
  customCron: "",
};

export const reportCronFromCadence = (cadence: ReportCadence): string => {
  switch (cadence.preset) {
    case REPORT_SCHEDULE_PRESET.DAILY:
      return `0 ${cadence.hour} * * *`;
    case REPORT_SCHEDULE_PRESET.WEEKLY:
      return `0 ${cadence.hour} * * ${cadence.weekday}`;
    case REPORT_SCHEDULE_PRESET.MONTHLY:
      return `0 ${cadence.hour} ${cadence.dayOfMonth} * *`;
    case REPORT_SCHEDULE_PRESET.CUSTOM:
      return cadence.customCron.trim();
    default:
      return cadence.customCron.trim();
  }
};

export const reportCadenceFromCron = (cron: string): ReportCadence => {
  const trimmed = cron.trim();
  const daily = /^0 (\d{1,2}) \* \* \*$/.exec(trimmed);
  if (daily) {
    return {
      ...DEFAULT_REPORT_CADENCE,
      preset: REPORT_SCHEDULE_PRESET.DAILY,
      hour: Number(daily[1]),
    };
  }
  const weekly = /^0 (\d{1,2}) \* \* (\d)$/.exec(trimmed);
  if (weekly) {
    return {
      ...DEFAULT_REPORT_CADENCE,
      preset: REPORT_SCHEDULE_PRESET.WEEKLY,
      hour: Number(weekly[1]),
      weekday: Number(weekly[2]),
    };
  }
  const monthly = /^0 (\d{1,2}) (\d{1,2}) \* \*$/.exec(trimmed);
  if (monthly) {
    return {
      ...DEFAULT_REPORT_CADENCE,
      preset: REPORT_SCHEDULE_PRESET.MONTHLY,
      hour: Number(monthly[1]),
      dayOfMonth: Number(monthly[2]),
    };
  }
  return {
    ...DEFAULT_REPORT_CADENCE,
    preset: REPORT_SCHEDULE_PRESET.CUSTOM,
    customCron: trimmed,
  };
};

/** Plain-language cadence for tables ("Weekly on Monday at 08:00"). */
export const describeReportCron = (cron: string, timezone: string): string => {
  const cadence = reportCadenceFromCron(cron);
  const at = `${String(cadence.hour).padStart(2, "0")}:00 ${timezone}`;
  switch (cadence.preset) {
    case REPORT_SCHEDULE_PRESET.DAILY:
      return `Daily at ${at}`;
    case REPORT_SCHEDULE_PRESET.WEEKLY: {
      const day =
        WEEKDAY_OPTIONS.find((option) => option.value === cadence.weekday)
          ?.label ?? `day ${cadence.weekday}`;
      return `Weekly on ${day} at ${at}`;
    }
    case REPORT_SCHEDULE_PRESET.MONTHLY:
      return `Monthly on day ${cadence.dayOfMonth} at ${at}`;
    default:
      return `${cron} (${timezone})`;
  }
};
