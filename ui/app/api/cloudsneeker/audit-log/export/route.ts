// Same-origin CSV export proxy for the audit log. The browser cannot send
// the session's API token itself, so this handler forwards it with an
// allow-listed set of filters and streams the API's CSV back.

import { NextResponse } from "next/server";

import { auditExportUpstreamQuery } from "@/cloudsneeker/lib/audit-log";
import { apiBaseUrl, getAuthHeaders } from "@/lib";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const FALLBACK_FILENAME = "audit-log.csv";

const noStoreJson = (error: string, status: number) =>
  NextResponse.json(
    { error },
    { status, headers: { "Cache-Control": "no-store" } },
  );

export async function GET(request: Request) {
  const query = auditExportUpstreamQuery(new URL(request.url).searchParams);
  if (new URLSearchParams(query).get("format") !== "csv") {
    return noStoreJson("Unknown format.", 400);
  }

  const headers = await getAuthHeaders({ contentType: false });
  const upstreamUrl = `${apiBaseUrl}/audit-events/export?${query}`;

  let upstream: Response;
  try {
    upstream = await fetch(upstreamUrl, { headers, cache: "no-store" });
  } catch {
    return noStoreJson("The audit log service is unavailable.", 502);
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

  if (!upstream.body) return noStoreJson("The export was empty.", 502);

  return new Response(upstream.body, {
    status: 200,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": upstream.headers.get("content-type") || "text/csv",
      "Content-Disposition":
        upstream.headers.get("content-disposition") ||
        `attachment; filename="${FALLBACK_FILENAME}"`,
    },
  });
}
