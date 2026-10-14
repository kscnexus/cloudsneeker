import { describe, expect, it } from "vitest";

import {
  CUSTODIAN_SCHEDULE_PRESET,
  cronFromPreset,
  presetFromCron,
} from "./custodian-schedule";

describe("cronFromPreset", () => {
  it("maps hourly", () => {
    expect(
      cronFromPreset({
        preset: CUSTODIAN_SCHEDULE_PRESET.HOURLY,
        hour: 9,
        weekday: 1,
        customCron: "",
      }),
    ).toEqual({ enabled: true, cron: "0 * * * *" });
  });

  it("maps daily with hour", () => {
    expect(
      cronFromPreset({
        preset: CUSTODIAN_SCHEDULE_PRESET.DAILY,
        hour: 14,
        weekday: 1,
        customCron: "",
      }),
    ).toEqual({ enabled: true, cron: "0 14 * * *" });
  });

  it("maps weekly with day and hour", () => {
    expect(
      cronFromPreset({
        preset: CUSTODIAN_SCHEDULE_PRESET.WEEKLY,
        hour: 8,
        weekday: 5,
        customCron: "",
      }),
    ).toEqual({ enabled: true, cron: "0 8 * * 5" });
  });

  it("maps disabled", () => {
    expect(
      cronFromPreset({
        preset: CUSTODIAN_SCHEDULE_PRESET.DISABLED,
        hour: 9,
        weekday: 1,
        customCron: "0 9 * * *",
      }),
    ).toEqual({ enabled: false, cron: "" });
  });
});

describe("presetFromCron", () => {
  it("detects daily", () => {
    expect(presetFromCron(true, "0 9 * * *")).toEqual({
      preset: CUSTODIAN_SCHEDULE_PRESET.DAILY,
      hour: 9,
      weekday: 1,
    });
  });

  it("falls back to custom", () => {
    expect(presetFromCron(true, "15 */2 * * 1-5").preset).toBe(
      CUSTODIAN_SCHEDULE_PRESET.CUSTOM,
    );
  });
});
