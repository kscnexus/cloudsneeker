import { ScanSearch } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import {
  getTrivyTarget,
  listTrivyRuns,
} from "@/cloudsneeker/actions/trivy";
import { AppSecurityRunList } from "@/cloudsneeker/components/app-security-run-list";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { TrivyScanButton } from "@/cloudsneeker/components/trivy-scan-button";
import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
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
      <PageHeader
        description={target.attributes.description || "No description"}
        meta={[
          { label: "Mode", value: labelForTrivyMode(target.attributes.mode) },
          {
            label: "Provider",
            value:
              target.attributes.provider_alias ||
              target.attributes.provider_uid ||
              target.attributes.provider_id,
          },
          {
            label: "Schedule",
            value: target.attributes.schedule_enabled
              ? `${target.attributes.schedule_cron} (${target.attributes.schedule_timezone || "UTC"})`
              : "Off",
          },
        ]}
        actions={
          <>
            <Button asChild variant="ghost" size="sm">
              <Link href={appSecurityHref(targetId, "edit")}>Edit</Link>
            </Button>
            <TrivyScanButton targetId={targetId} />
          </>
        }
      />

      <div className="flex flex-col gap-6">
        <SectionCard
          title="Run history"
          description="Newest first. Each completed scan adds its results to Findings."
        >
          <AppSecurityRunList
            runs={runs}
            showTarget={false}
            emptyMessage="No runs yet. Start a scan to populate Findings."
          />
        </SectionCard>

        <SectionCard title="Config">
          <pre className="bg-bg-neutral-tertiary overflow-x-auto rounded-lg p-4 text-sm">
            {JSON.stringify(target.attributes.config ?? {}, null, 2)}
          </pre>
        </SectionCard>
      </div>
    </ContentLayout>
  );
}
