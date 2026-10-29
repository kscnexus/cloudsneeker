// Same-origin download proxy for report artifacts. The browser cannot send
// the session's API token itself, so this handler forwards it and streams the
// API's file back with its content type and branded file name.

import { NextResponse } from "next/server";

import {
  buildReportDownloadHeaders,
  isDownloadableReportFormat,
  isReportRunId,
} from "@/cloudsneeker/lib/report-download";
import { REPORT_FORMAT } from "@/cloudsneeker/types/reports";
import { apiBaseUrl, getAuthHeaders } from "@/lib";

const noStoreJson = (error: string, status: number) =>
  NextResponse.json(
    { error },
    { status, headers: { "Cache-Control": "no-store" } },
  );

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

interface ReportDownloadRouteContext {
  params: Promise<{ runId: string }>;
}

export async function GET(
  request: Request,
  { params }: ReportDownloadRouteContext,
) {
  const { runId } = await params;
  const format = (
    new URL(request.url).searchParams.get("format") ?? REPORT_FORMAT.PDF
  ).toLowerCase();

  if (!isReportRunId(runId)) return noStoreJson("Unknown report.", 404);
  if (!isDownloadableReportFormat(format)) {
    return noStoreJson("Unknown format.", 400);
  }

  const headers = await getAuthHeaders({ contentType: false });
  const upstreamUrl = `${apiBaseUrl}/report-runs/${encodeURIComponent(runId)}/download?format=${encodeURIComponent(format)}`;

  let upstream: Response;
  try {
    upstream = await fetch(upstreamUrl, { headers, cache: "no-store" });
  } catch {
    return noStoreJson("The report service is unavailable.", 502);
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

  if (!upstream.body) {
    return noStoreJson("The report file was empty.", 502);
  }

  return new Response(upstream.body, {
    status: 200,
    headers: buildReportDownloadHeaders(upstream.headers, runId, format),
  });
}
