import { NextResponse } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { HSTS_ENV, HSTS_HEADER } from "./hsts";
import {
  applySecurityHeaders,
  PERMISSIONS_POLICY,
  PERMISSIONS_POLICY_HEADER,
} from "./security-headers";

describe("applySecurityHeaders", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("turns off unused browser features", () => {
    const response = applySecurityHeaders(NextResponse.next());
    expect(response.headers.get(PERMISSIONS_POLICY_HEADER)).toBe(
      PERMISSIONS_POLICY,
    );
    expect(PERMISSIONS_POLICY).toContain("camera=()");
  });

  it("still adds HSTS on HTTPS stacks", () => {
    vi.stubEnv(HSTS_ENV, "31536000");
    const response = applySecurityHeaders(NextResponse.next());
    expect(response.headers.get(HSTS_HEADER)).toContain("max-age=31536000");
  });
});
