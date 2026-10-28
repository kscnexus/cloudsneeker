import { afterEach, describe, expect, it, vi } from "vitest";

import { localTimeZoneLabel } from "./time-zone";

describe("localTimeZoneLabel", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns the short time zone name for the date", () => {
    vi.spyOn(Intl.DateTimeFormat.prototype, "formatToParts").mockReturnValue([
      { type: "hour", value: "9" },
      { type: "timeZoneName", value: "GMT+5:30" },
    ]);

    expect(localTimeZoneLabel(new Date("2026-10-28T15:30:00Z"))).toBe(
      "GMT+5:30",
    );
  });

  it("never returns a truncated city name", () => {
    expect(localTimeZoneLabel(new Date("2026-10-28T15:30:00Z"))).not.toBe(
      "CAL",
    );
  });

  it("returns an empty label when the zone name is unavailable", () => {
    vi.spyOn(Intl.DateTimeFormat.prototype, "formatToParts").mockReturnValue([
      { type: "hour", value: "9" },
    ]);

    expect(localTimeZoneLabel(new Date("2026-10-28T15:30:00Z"))).toBe("");
  });
});
