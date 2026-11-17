import { ScanSearch } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import {
  getTrivyTarget,
  listTrivyRuns,
  listTrivyTargets,
} from "@/cloudsneeker/actions/trivy";
import { AppSecurityRunList } from "@/cloudsneeker/components/app-security-run-list";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { TargetBranchScan } from "@/cloudsneeker/components/target-branch-scan";
import {
  type MergeCandidate,
  TargetMergePanel,
} from "@/cloudsneeker/components/target-merge-panel";
import { TargetReportDownloadButton } from "@/cloudsneeker/components/target-report-download-button";
import { TrivyScanButton } from "@/cloudsneeker/components/trivy-scan-button";
import { branchDisplay } from "@/cloudsneeker/lib/repository-branches";
import {
  reportTypeForTargetMode,
  TARGET_REPORT_LABEL,
} from "@/cloudsneeker/lib/target-reports";
import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import {
  TRIVY_MODE,
  type TrivyRunResource,
  type TrivyTargetResource,
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
  const reportType = reportTypeForTargetMode(target.attributes.mode);
  const config = target.attributes.config ?? {};
  // Git targets: the chosen branch, else the default branch the latest
  // run checked out.
  const scannedBranch = runs.find((run) => run.attributes.branch)?.attributes
    .branch;
  const branch = !config.repository_url
    ? ""
    : config.branch ||
      (scannedBranch ? `${scannedBranch} (default)` : branchDisplay(""));
  const extraBranches = Array.isArray(config.branches) ? config.branches : [];
  const isGitTarget =
    Boolean(config.repository_url) &&
    (target.attributes.mode === TRIVY_MODE.REPO ||
      target.attributes.mode === TRIVY_MODE.SAST);

  // Other targets of the same repository that can be folded into this one.
  let mergeCandidates: MergeCandidate[] = [];
  if (isGitTarget) {
    const siblings = await listTrivyTargets({
      "filter[provider]": target.attributes.provider_id,
      "page[size]": "100",
    });
    const allowedModes: string[] =
      target.attributes.mode === TRIVY_MODE.REPO
        ? [TRIVY_MODE.REPO, TRIVY_MODE.SAST]
        : [TRIVY_MODE.SAST];
    mergeCandidates = ((siblings?.data ?? []) as TrivyTargetResource[])
      .filter(
        (item) =>
          item.id !== targetId &&
          allowedModes.includes(item.attributes.mode) &&
          Boolean(item.attributes.config?.repository_url),
      )
      .map((item) => ({
        id: item.id,
        name: item.attributes.name,
        mode: item.attributes.mode,
        branch: item.attributes.config?.branch ?? "",
      }));
  }

  return (
    <ContentLayout title={target.attributes.name} icon={<ScanSearch />}>
      <PageHeader
        description={target.attributes.description || "No description"}
        meta={[
          { label: "Mode", value: labelForTrivyMode(target.attributes.mode) },
          ...(branch ? [{ label: "Branch", value: branch }] : []),
          ...(extraBranches.length > 0
            ? [{ label: "Other branches", value: extraBranches.join(", ") }]
            : []),
          ...(config.sast ? [{ label: "Static analysis", value: "On" }] : []),
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
            {reportType ? (
              <TargetReportDownloadButton
                label={`Download ${TARGET_REPORT_LABEL[reportType]}`}
                jobs={[
                  {
                    targetId,
                    targetName: target.attributes.name,
                    reportType,
                  },
                ]}
              />
            ) : null}
            <TrivyScanButton targetId={targetId} />
          </>
        }
      />

      <div className="flex flex-col gap-6">
        {isGitTarget ? (
          <SectionCard
            title="Branches"
            description="One target covers every branch. Each scan runs the main branch, then the other branches that changed since their last scan."
          >
            <TargetBranchScan
              targetId={targetId}
              extraBranches={extraBranches}
            />
          </SectionCard>
        ) : null}

        {mergeCandidates.length > 0 ? (
          <SectionCard
            title="Duplicate targets of this repository"
            description="Fold them into this target. Static analysis targets turn static analysis on here; targets of other branches become other branches. Findings, history and triage move with them."
          >
            <TargetMergePanel
              targetId={targetId}
              candidates={mergeCandidates}
            />
          </SectionCard>
        ) : null}

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
