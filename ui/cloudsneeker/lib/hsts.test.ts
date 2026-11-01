import { NextResponse } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { applyHsts, HSTS_ENV, HSTS_HEADER, hstsHeaderValue } from "./hsts";

describe("hstsHeaderValue", () => {
  it("builds the header from a positive number of seconds", () => {
    expect(hstsHeaderValue("31536000")).toBe(
      "max-age=31536000; includeSubDomains",
    );
  });

  it.each([undefined, "", "0", "-5", "soon"])("is off for %j", (raw) => {
    expect(hstsHeaderValue(raw)).toBeNull();
  });
});

describe("applyHsts", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("sets the header when the stack serves HTTPS", () => {
    vi.stubEnv(HSTS_ENV, "31536000");
    const response = applyHsts(NextResponse.next());
    expect(response.headers.get(HSTS_HEADER)).toBe(
      "max-age=31536000; includeSubDomains",
    );
  });

  it("leaves plain-HTTP installs alone", () => {
    const response = applyHsts(NextResponse.next());
    expect(response.headers.get(HSTS_HEADER)).toBeNull();
  });
});
