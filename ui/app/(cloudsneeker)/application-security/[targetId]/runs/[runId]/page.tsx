import { ScanSearch } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import { getTrivyRun } from "@/cloudsneeker/actions/trivy";
import { BRAND } from "@/cloudsneeker/brand";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { RunStatusBadge } from "@/cloudsneeker/components/run-status-badge";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  findingsHrefForScan,
  labelForTrivyMode,
} from "@/cloudsneeker/lib/trivy-modes";
import { appSecurityHref } from "@/cloudsneeker/routes";
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
      title={run.attributes.target_name || `${BRAND.appSecurityName} scan`}
      icon={<ScanSearch />}
    >
      <PageHeader
        meta={[
          {
            label: "Status",
            value: <RunStatusBadge status={run.attributes.status} />,
          },
          { label: "Trigger", value: run.attributes.trigger },
          {
            label: "Mode",
            value: labelForTrivyMode(
              run.attributes.target_mode || run.attributes.summary?.mode || "",
            ),
          },
          ...(typeof run.attributes.summary?.finding_count === "number"
            ? [
                {
                  label: "Findings imported",
                  value: run.attributes.summary.finding_count,
                },
              ]
            : []),
        ]}
        actions={
          <>
            <Button asChild variant="ghost" size="sm">
              <Link href={appSecurityHref(targetId)}>Back to target</Link>
            </Button>
            {scanId ? (
              <Button asChild size="sm">
                <Link href={findingsHrefForScan(scanId)}>Open findings</Link>
              </Button>
            ) : null}
          </>
        }
      >
        {run.attributes.error ? (
          <p className="text-text-error-primary text-sm">
            {run.attributes.error}
          </p>
        ) : null}
      </PageHeader>

      <SectionCard title="Summary">
        <pre className="bg-bg-neutral-tertiary overflow-x-auto rounded-lg p-4 text-sm">
          {JSON.stringify(run.attributes.summary ?? {}, null, 2)}
        </pre>
      </SectionCard>
    </ContentLayout>
  );
}
