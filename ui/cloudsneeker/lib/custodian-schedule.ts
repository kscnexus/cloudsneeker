export const CUSTODIAN_SCHEDULE_PRESET = {
  DISABLED: "disabled",
  HOURLY: "hourly",
  DAILY: "daily",
  WEEKLY: "weekly",
  CUSTOM: "custom",
} as const;

export type CustodianSchedulePreset =
  (typeof CUSTODIAN_SCHEDULE_PRESET)[keyof typeof CUSTODIAN_SCHEDULE_PRESET];

export interface CustodianScheduleFields {
  scheduleEnabled: boolean;
  scheduleCron: string;
  scheduleTimezone: string;
  schedulePreset: CustodianSchedulePreset;
  scheduleHour: number;
  scheduleWeekday: number;
}

export const cronFromPreset = (fields: {
  preset: CustodianSchedulePreset;
  hour: number;
  weekday: number;
  customCron: string;
}): { enabled: boolean; cron: string } => {
  switch (fields.preset) {
    case CUSTODIAN_SCHEDULE_PRESET.DISABLED:
      return { enabled: false, cron: "" };
    case CUSTODIAN_SCHEDULE_PRESET.HOURLY:
      return { enabled: true, cron: "0 * * * *" };
    case CUSTODIAN_SCHEDULE_PRESET.DAILY:
      return { enabled: true, cron: `0 ${fields.hour} * * *` };
    case CUSTODIAN_SCHEDULE_PRESET.WEEKLY:
      return {
        enabled: true,
        cron: `0 ${fields.hour} * * ${fields.weekday}`,
      };
    case CUSTODIAN_SCHEDULE_PRESET.CUSTOM:
      return { enabled: true, cron: fields.customCron.trim() };
    default:
      return { enabled: false, cron: "" };
  }
};

export const presetFromCron = (
  enabled: boolean,
  cron: string,
): {
  preset: CustodianSchedulePreset;
  hour: number;
  weekday: number;
} => {
  if (!enabled || !cron.trim()) {
    return {
      preset: CUSTODIAN_SCHEDULE_PRESET.DISABLED,
      hour: 9,
      weekday: 1,
    };
  }
  const trimmed = cron.trim();
  if (trimmed === "0 * * * *") {
    return {
      preset: CUSTODIAN_SCHEDULE_PRESET.HOURLY,
      hour: 9,
      weekday: 1,
    };
  }
  const daily = /^0 (\d{1,2}) \* \* \*$/.exec(trimmed);
  if (daily) {
    return {
      preset: CUSTODIAN_SCHEDULE_PRESET.DAILY,
      hour: Number(daily[1]),
      weekday: 1,
    };
  }
  const weekly = /^0 (\d{1,2}) \* \* (\d)$/.exec(trimmed);
  if (weekly) {
    return {
      preset: CUSTODIAN_SCHEDULE_PRESET.WEEKLY,
      hour: Number(weekly[1]),
      weekday: Number(weekly[2]),
    };
  }
  return {
    preset: CUSTODIAN_SCHEDULE_PRESET.CUSTOM,
    hour: 9,
    weekday: 1,
  };
};
