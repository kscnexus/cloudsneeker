// HTTP Strict Transport Security for the web app (EB-015). The stack sets
// CLOUDSNEEKER_HSTS_SECONDS only when it serves HTTPS on its own domain, so a
// plain-HTTP install never tells browsers to refuse it. Read per request in
// `proxy.ts`: `next.config.js` headers are fixed at build time.

import type { NextResponse } from "next/server";

export const HSTS_ENV = "CLOUDSNEEKER_HSTS_SECONDS";
export const HSTS_HEADER = "Strict-Transport-Security";

/** Header value, or `null` when HSTS is off (unset, zero or invalid). */
export const hstsHeaderValue = (
  raw: string | undefined = process.env[HSTS_ENV],
): string | null => {
  const seconds = Number.parseInt((raw ?? "").trim(), 10);
  if (!Number.isFinite(seconds) || seconds <= 0) return null;
  return `max-age=${seconds}; includeSubDomains`;
};

export const applyHsts = (response: NextResponse): NextResponse => {
  const value = hstsHeaderValue();
  if (value) response.headers.set(HSTS_HEADER, value);
  return response;
};
