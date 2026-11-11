// Same-origin download proxy for Application Security files (SBOMs, scan
// reports, finding exports). The browser cannot send the session's API token
// itself, so this handler forwards it and streams the API's file back.

import { NextResponse } from "next/server";

import {
  buildAppSecDownloadHeaders,
  resolveAppSecDownload,
} from "@/cloudsneeker/lib/appsec-download";
import { apiBaseUrl, getAuthHeaders } from "@/lib";

const noStoreJson = (error: string, status: number) =>
  NextResponse.json(
    { error },
    { status, headers: { "Cache-Control": "no-store" } },
  );

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request: Request) {
  const target = resolveAppSecDownload(new URL(request.url).searchParams);
  if (typeof target === "string") return noStoreJson(target, 400);

  const headers = await getAuthHeaders({ contentType: false });
  let upstream: Response;
  try {
    upstream = await fetch(`${apiBaseUrl}${target.path}`, {
      headers,
      cache: "no-store",
    });
  } catch {
    return noStoreJson("The service is unavailable.", 502);
  }

  if (!upstream.ok) {
    const body = await upstream.text().catch(() => "");
    return new Response(body, {
      status: upstream.status,
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": upstream.headers.get("content-type") || "text/plain",
      },
    });
  }
  if (!upstream.body) return noStoreJson("The file was empty.", 502);

  return new Response(upstream.body, {
    status: 200,
    headers: buildAppSecDownloadHeaders(upstream.headers, target.fallbackName),
  });
}
