import { ScanSearch } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import { getTrivyRun } from "@/cloudsneeker/actions/trivy";
import {
  findingsHrefForScan,
  labelForTrivyMode,
} from "@/cloudsneeker/lib/trivy-modes";
import type { TrivyRunResource } from "@/cloudsneeker/types/trivy";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";

interface TrivyRunDetailPageProps {
  params: Promise<{ targetId: string; runId: string }>;
}

export default async function TrivyRunDetailPage({
  params,
}: TrivyRunDetailPageProps) {
  const { targetId, runId } = await params;
  const runResponse = await getTrivyRun(runId);

  if (
    !runResponse ||
    ("error" in runResponse && runResponse.error) ||
    !runResponse.data ||
    Array.isArray(runResponse.data)
  ) {
    notFound();
  }

  const run = runResponse.data as TrivyRunResource;
  const scanId = run.attributes.scan_id || run.attributes.summary?.scan_id;

  return (
    <ContentLayout
      title={run.attributes.target_name || "Trivy run"}
      icon={<ScanSearch />}
    >
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="flex flex-col gap-1">
          <p className="text-text-neutral-secondary text-sm">
            Status: {run.attributes.status} · Trigger: {run.attributes.trigger}
          </p>
          <p className="text-text-neutral-secondary text-sm">
            Mode:{" "}
            {labelForTrivyMode(
              run.attributes.target_mode || run.attributes.summary?.mode || "",
            )}
          </p>
          {typeof run.attributes.summary?.finding_count === "number" ? (
            <p className="text-text-neutral-secondary text-sm">
              Findings imported: {run.attributes.summary.finding_count}
            </p>
          ) : null}
          {run.attributes.error ? (
            <p className="text-text-error-primary text-sm">
              {run.attributes.error}
            </p>
          ) : null}
        </div>
        <div className="flex gap-2">
          <Button asChild variant="ghost" size="sm">
            <Link href={`/trivy/${targetId}`}>Back to target</Link>
          </Button>
          {scanId ? (
            <Button asChild size="sm">
              <Link href={findingsHrefForScan(scanId)}>Open findings</Link>
            </Button>
          ) : null}
        </div>
      </div>

      <section className="flex flex-col gap-2">
        <h2 className="text-text-neutral-primary text-base font-semibold">
          Summary
        </h2>
        <pre className="border-border-neutral-secondary bg-bg-neutral-secondary overflow-x-auto rounded-xl border p-4 text-sm">
          {JSON.stringify(run.attributes.summary ?? {}, null, 2)}
        </pre>
      </section>
    </ContentLayout>
  );
}
