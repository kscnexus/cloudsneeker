import { describe, expect, it } from "vitest";

import {
  DEFAULT_REPORT_CADENCE,
  describeReportCron,
  REPORT_SCHEDULE_PRESET,
  reportCadenceFromCron,
  reportCronFromCadence,
} from "@/cloudsneeker/lib/report-schedule";

describe("report schedule cadence", () => {
  it("builds cron for each preset", () => {
    const cadence = { ...DEFAULT_REPORT_CADENCE, hour: 9 };
    expect(
      reportCronFromCadence({ ...cadence, preset: REPORT_SCHEDULE_PRESET.DAILY }),
    ).toBe("0 9 * * *");
    expect(
      reportCronFromCadence({
        ...cadence,
        preset: REPORT_SCHEDULE_PRESET.WEEKLY,
        weekday: 3,
      }),
    ).toBe("0 9 * * 3");
    expect(
      reportCronFromCadence({
        ...cadence,
        preset: REPORT_SCHEDULE_PRESET.MONTHLY,
        dayOfMonth: 20,
      }),
    ).toBe("0 9 20 * *");
    expect(
      reportCronFromCadence({
        ...cadence,
        preset: REPORT_SCHEDULE_PRESET.CUSTOM,
        customCron: " */15 * * * * ",
      }),
    ).toBe("*/15 * * * *");
  });

  it("reads presets back from cron", () => {
    expect(reportCadenceFromCron("0 7 * * *")).toMatchObject({
      preset: REPORT_SCHEDULE_PRESET.DAILY,
      hour: 7,
    });
    expect(reportCadenceFromCron("0 7 * * 0")).toMatchObject({
      preset: REPORT_SCHEDULE_PRESET.WEEKLY,
      weekday: 0,
    });
    expect(reportCadenceFromCron("0 7 28 * *")).toMatchObject({
      preset: REPORT_SCHEDULE_PRESET.MONTHLY,
      dayOfMonth: 28,
    });
    expect(reportCadenceFromCron("30 9 * * 1-5")).toMatchObject({
      preset: REPORT_SCHEDULE_PRESET.CUSTOM,
      customCron: "30 9 * * 1-5",
    });
  });

  it("describes a cadence in plain language", () => {
    expect(describeReportCron("0 8 * * 1", "UTC")).toBe(
      "Weekly on Monday at 08:00 UTC",
    );
    expect(describeReportCron("0 6 1 * *", "Asia/Kolkata")).toBe(
      "Monthly on day 1 at 06:00 Asia/Kolkata",
    );
    expect(describeReportCron("30 9 * * 1-5", "UTC")).toBe(
      "30 9 * * 1-5 (UTC)",
    );
  });
});
