import { afterEach, describe, expect, it, vi } from "vitest";

import { isSelfRegistrationEnabled } from "@/lib/shared/env";

import {
  isCloudsneekerSelfRegistrationEnabled,
  SELF_REGISTRATION_ENV,
} from "./self-registration";

describe("isCloudsneekerSelfRegistrationEnabled", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("is on when the env var is unset", () => {
    expect(isCloudsneekerSelfRegistrationEnabled()).toBe(true);
  });

  it.each(["true", "", "yes"])('is on for "%s"', (value) => {
    vi.stubEnv(SELF_REGISTRATION_ENV, value);
    expect(isCloudsneekerSelfRegistrationEnabled()).toBe(true);
  });

  it.each(["false", "FALSE", " False "])('is off for "%s"', (value) => {
    vi.stubEnv(SELF_REGISTRATION_ENV, value);
    expect(isCloudsneekerSelfRegistrationEnabled()).toBe(false);
  });
});

describe("isSelfRegistrationEnabled outside cloud mode", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    document.head.innerHTML = "";
  });

  it("follows the Cloudsneeker switch", () => {
    vi.stubEnv(SELF_REGISTRATION_ENV, "false");
    expect(isSelfRegistrationEnabled()).toBe(false);
  });

  it("stays open when the switch is unset", () => {
    expect(isSelfRegistrationEnabled()).toBe(true);
  });

  it("ignores the switch in cloud mode", () => {
    vi.stubEnv("UI_CLOUD_ENABLED", "true");
    vi.stubEnv(SELF_REGISTRATION_ENV, "false");
    expect(isSelfRegistrationEnabled()).toBe(true);
  });
});
