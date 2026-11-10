// Response headers Cloudsneeker adds on top of upstream's CSP in `proxy.ts`.
// The app uses no camera, microphone, location, USB or payment APIs, so
// Permissions-Policy turns them off for the page and anything it frames.

import type { NextResponse } from "next/server";

import { applyHsts } from "./hsts";

export const PERMISSIONS_POLICY_HEADER = "Permissions-Policy";
export const PERMISSIONS_POLICY =
  "camera=(), microphone=(), geolocation=(), usb=(), payment=()";

export const applySecurityHeaders = (response: NextResponse): NextResponse => {
  response.headers.set(PERMISSIONS_POLICY_HEADER, PERMISSIONS_POLICY);
  return applyHsts(response);
};
