import { describe, expect, it } from "vitest";

import {
  buildGithubTargetBody,
  GITHUB_DAILY_SCAN_CRON,
} from "./github-repositories";

const REPOSITORY = {
  full_name: "acme/api",
  repository_url: "https://github.com/acme/api",
};

describe("buildGithubTargetBody", () => {
  it("creates a code repository target that runs every day", () => {
    const body = buildGithubTargetBody("provider-1", REPOSITORY, {
      dailySchedule: true,
      timezone: "Asia/Kolkata",
    });

    expect(body.data.attributes).toMatchObject({
      name: "acme/api",
      mode: "repo",
      provider_id: "provider-1",
      schedule_enabled: true,
      schedule_cron: GITHUB_DAILY_SCAN_CRON,
      schedule_timezone: "Asia/Kolkata",
    });
    expect(body.data.attributes.config.repository_url).toBe(
      "https://github.com/acme/api",
    );
  });

  it("leaves the schedule off when daily scans are not wanted", () => {
    const body = buildGithubTargetBody("provider-1", REPOSITORY, {
      dailySchedule: false,
      timezone: "",
    });

    expect(body.data.attributes).toMatchObject({
      schedule_enabled: false,
      schedule_cron: "",
      schedule_timezone: "UTC",
    });
  });
});
