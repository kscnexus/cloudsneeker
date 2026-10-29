import { ScanSearch } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import {
  getTrivyTarget,
  listTrivyRuns,
} from "@/cloudsneeker/actions/trivy";
import { TrivyScanButton } from "@/cloudsneeker/components/trivy-scan-button";
import {
  findingsHrefForScan,
  labelForTrivyMode,
} from "@/cloudsneeker/lib/trivy-modes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import type {
  TrivyRunResource,
  TrivyTargetResource,
} from "@/cloudsneeker/types/trivy";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";

interface TrivyTargetDetailPageProps {
  params: Promise<{ targetId: string }>;
}

export default async function TrivyTargetDetailPage({
  params,
}: TrivyTargetDetailPageProps) {
  const { targetId } = await params;
  const targetResponse = await getTrivyTarget(targetId);

  if (
    !targetResponse ||
    ("error" in targetResponse && targetResponse.error) ||
    !targetResponse.data ||
    Array.isArray(targetResponse.data)
  ) {
    notFound();
  }

  const target = targetResponse.data as TrivyTargetResource;
  const runsResponse = await listTrivyRuns({
    "filter[target]": targetId,
    "page[size]": "20",
    sort: "-inserted_at",
  });
  const runs = (runsResponse?.data ?? []) as TrivyRunResource[];

  return (
    <ContentLayout title={target.attributes.name} icon={<ScanSearch />}>
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="flex max-w-2xl flex-col gap-1">
          <p className="text-text-neutral-secondary text-sm">
            {target.attributes.description || "No description"}
          </p>
          <p className="text-text-neutral-secondary text-sm">
            Mode: {labelForTrivyMode(target.attributes.mode)}
          </p>
          <p className="text-text-neutral-secondary text-sm">
            Provider:{" "}
            {target.attributes.provider_alias ||
              target.attributes.provider_uid ||
              target.attributes.provider_id}
          </p>
          {target.attributes.schedule_enabled ? (
            <p className="text-text-neutral-secondary text-sm">
              Schedule: {target.attributes.schedule_cron} (
              {target.attributes.schedule_timezone || "UTC"})
            </p>
          ) : (
            <p className="text-text-neutral-secondary text-sm">Schedule: off</p>
          )}
        </div>
        <div className="flex gap-2">
          <Button asChild variant="ghost" size="sm">
            <Link href={appSecurityHref(targetId, "edit")}>Edit</Link>
          </Button>
          <TrivyScanButton targetId={targetId} />
        </div>
      </div>

      <section className="mb-8 flex flex-col gap-2">
        <h2 className="text-text-neutral-primary text-base font-semibold">
          Config
        </h2>
        <pre className="border-border-neutral-secondary bg-bg-neutral-secondary overflow-x-auto rounded-xl border p-4 text-sm">
          {JSON.stringify(target.attributes.config ?? {}, null, 2)}
        </pre>
      </section>

      <section className="flex flex-col gap-3">
        <h2 className="text-text-neutral-primary text-base font-semibold">
          Run history
        </h2>
        {runs.length === 0 ? (
          <p className="text-text-neutral-secondary text-sm">
            No runs yet. Start a scan to populate Findings.
          </p>
        ) : (
          <ul className="divide-border-neutral-secondary border-border-neutral-secondary divide-y rounded-xl border">
            {runs.map((run) => {
              const scanId =
                run.attributes.scan_id || run.attributes.summary?.scan_id;
              return (
                <li key={run.id} className="flex flex-col gap-1 px-4 py-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <Link
                      href={appSecurityHref(targetId, "runs", run.id)}
                      className="text-text-neutral-primary font-medium underline-offset-2 hover:underline"
                    >
                      {run.attributes.status}
                    </Link>
                    <span className="text-text-neutral-secondary text-xs">
                      {run.attributes.trigger}
                      {run.attributes.finished_at
                        ? ` · ${new Date(run.attributes.finished_at).toLocaleString()}`
                        : ""}
                    </span>
                  </div>
                  {run.attributes.error ? (
                    <p className="text-text-error-primary text-xs">
                      {run.attributes.error}
                    </p>
                  ) : null}
                  {scanId ? (
                    <Link
                      href={findingsHrefForScan(scanId)}
                      className="text-text-neutral-secondary text-xs underline"
                    >
                      Open findings
                    </Link>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </section>
    </ContentLayout>
  );
}
