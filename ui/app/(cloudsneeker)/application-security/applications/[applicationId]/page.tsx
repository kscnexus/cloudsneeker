import { AppWindow, FileText, ListChecks, Plus } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Suspense } from "react";

import { listTrivyRuns } from "@/cloudsneeker/actions/trivy";
import { BRAND } from "@/cloudsneeker/brand";
import { AppSecurityRunList } from "@/cloudsneeker/components/app-security-run-list";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { ProductPageTabs } from "@/cloudsneeker/components/product-page-tabs";
import { RiskPriorityBadge } from "@/cloudsneeker/components/risk-priority-badge";
import { RunStatusBadge } from "@/cloudsneeker/components/run-status-badge";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { STAT_TILE_TONE, StatTile } from "@/cloudsneeker/components/stat-tile";
import { TrivyTargetList } from "@/cloudsneeker/components/trivy-target-list";
import {
  type Application,
  APPLICATION_TAB,
  APPLICATION_TAB_PARAM,
  type ApplicationTab,
  applicationHref,
  applicationPostureLabel,
  applicationsHref,
  getApplicationTab,
  groupTargetsIntoApplications,
  scanTypeLabels,
} from "@/cloudsneeker/lib/app-security-applications";
import {
  loadAllTargets,
  loadApplicationFindingMeta,
  loadApplicationSummaries,
} from "@/cloudsneeker/lib/app-security-applications-data";
import { securityCategoryTabs } from "@/cloudsneeker/lib/app-security-categories";
import { newTargetHref } from "@/cloudsneeker/lib/app-security-dashboard";
import { RISK_PRIORITY_INFO } from "@/cloudsneeker/lib/app-security-priority";
import {
  applicationFindingsHref,
  formatRunTime,
  isApplicationId,
} from "@/cloudsneeker/lib/app-security-scans";
import {
  isListResponse,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import { CARD_LIST_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { reportsHref } from "@/cloudsneeker/routes";
import {
  type AreaFindingsResponse,
  RISK_PRIORITIES,
} from "@/cloudsneeker/types/area-findings";
import type { TrivyRunResource } from "@/cloudsneeker/types/trivy";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import type { SearchParamsProps } from "@/types";

/** Scans shown on the Scans tab, newest first. */
const RECENT_RUN_LIMIT = 50;

interface ApplicationDetailPageProps {
  params: Promise<{ applicationId: string }>;
  searchParams: Promise<SearchParamsProps>;
}

export default async function ApplicationDetailPage({
  params,
  searchParams,
}: ApplicationDetailPageProps) {
  const { applicationId } = await params;
  const activeTab = getApplicationTab(
    (await searchParams)[APPLICATION_TAB_PARAM],
  );
  if (!isApplicationId(applicationId)) notFound();

  const loaded = await loadAllTargets({ "filter[provider]": applicationId });
  if (!loaded) {
    return (
      <ContentLayout title={BRAND.appSecurityName} icon={<AppWindow />}>
        <SectionCard title="Application">
          <EmptyState
            title="Application could not be loaded"
            description="The service did not answer. Reload the page in a moment."
            action={
              <Button asChild size="sm" variant="outline">
                <Link href={applicationHref(applicationId, activeTab)}>
                  Reload
                </Link>
              </Button>
            }
          />
        </SectionCard>
      </ContentLayout>
    );
  }

  const application = groupTargetsIntoApplications(loaded.targets).find(
    (item) => item.id === applicationId,
  );
  if (!application) notFound();

  return (
    <ContentLayout title={application.name} icon={<AppWindow />}>
      <PageHeader
        description={`${BRAND.appSecurityName} application: every target that scans this source, with its findings and scans.`}
        meta={[
          { label: "Repository", value: application.repository || "—" },
          {
            label: "Scan types",
            value: scanTypeLabels(application).join(", ") || "—",
          },
          { label: "Targets", value: application.targets.length },
        ]}
        actions={
          <Button asChild size="sm" variant="outline">
            <Link href={applicationsHref()}>All applications</Link>
          </Button>
        }
      />
      <Suspense fallback={<Skeleton className="h-96 w-full rounded-xl" />}>
        <SSRApplicationWorkspace
          application={application}
          activeTab={activeTab}
        />
      </Suspense>
    </ContentLayout>
  );
}

type FindingMeta = AreaFindingsResponse["meta"] | null;

const LOAD_ERROR = "Findings could not be loaded. Reload the page in a moment.";

const ErrorMessage = ({ message = LOAD_ERROR }: { message?: string }) => (
  <p className="text-text-error-primary text-sm">{message}</p>
);

const CategoryList = ({
  applicationId,
  meta,
}: {
  applicationId: string;
  meta: NonNullable<FindingMeta>;
}) => (
  <ul className={CARD_LIST_CLASS}>
    {securityCategoryTabs(meta.category_counts, meta.enabled_categories).map(
      (tab) => (
        <li key={tab.category}>
          <Link
            href={applicationFindingsHref(applicationId, {
              category: tab.category,
            })}
            className="hover:bg-bg-neutral-tertiary flex items-center justify-between gap-3 px-4 py-2.5 text-sm transition-colors"
          >
            <span className="text-text-neutral-primary">{tab.label}</span>
            <span className="text-text-neutral-secondary tabular-nums">
              {tab.count}
            </span>
          </Link>
        </li>
      ),
    )}
  </ul>
);

const PriorityList = ({
  applicationId,
  meta,
}: {
  applicationId: string;
  meta: NonNullable<FindingMeta>;
}) => (
  <ul className={CARD_LIST_CLASS}>
    {RISK_PRIORITIES.map((priority) => (
      <li key={priority}>
        <Link
          href={applicationFindingsHref(applicationId, { priority })}
          className="hover:bg-bg-neutral-tertiary flex items-center justify-between gap-3 px-4 py-2.5 text-sm transition-colors"
          aria-label={`${RISK_PRIORITY_INFO[priority].code} ${RISK_PRIORITY_INFO[priority].label} findings`}
        >
          <RiskPriorityBadge priority={priority} />
          <span className="text-text-neutral-secondary tabular-nums">
            {meta.priority_counts?.[priority] ?? 0}
          </span>
        </Link>
      </li>
    ))}
  </ul>
);

const SSRApplicationWorkspace = async ({
  application,
  activeTab,
}: {
  application: Application;
  activeTab: ApplicationTab;
}) => {
  const id = application.id;
  const [meta, summaries, runsResponse] = await Promise.all([
    loadApplicationFindingMeta(id),
    loadApplicationSummaries(),
    listTrivyRuns({
      "filter[provider]": id,
      "filter[archived]": "false",
      "page[size]": String(RECENT_RUN_LIMIT),
      sort: "-inserted_at",
    }),
  ]);
  const summary = summaries?.find((item) => item.id === id);
  const runsLoaded = isListResponse(runsResponse);
  const runs = responseList<TrivyRunResource>(runsResponse);
  const lastRun = runs[0];
  const urgent =
    (meta?.priority_counts?.p0 ?? 0) + (meta?.priority_counts?.p1 ?? 0);
  const openTotal = summary?.total ?? meta?.pagination?.count;

  const reportsAction = (
    <div className="flex flex-wrap gap-2">
      <Button asChild size="sm" variant="outline">
        <Link href={applicationFindingsHref(id)}>
          <ListChecks aria-hidden="true" />
          Findings
        </Link>
      </Button>
      <Button asChild size="sm" variant="outline">
        <Link href={reportsHref()}>
          <FileText aria-hidden="true" />
          Reports
        </Link>
      </Button>
      <Button asChild size="sm">
        <Link href={newTargetHref(id)}>
          <Plus aria-hidden="true" />
          New target
        </Link>
      </Button>
    </div>
  );

  const overviewContent = (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile
          label="Open findings"
          value={openTotal ?? "—"}
          href={applicationFindingsHref(id)}
          tone={STAT_TILE_TONE.ACCENT}
        />
        <StatTile
          label="P0 / P1"
          value={meta ? urgent : "—"}
          hint="Fix within days"
          tone={STAT_TILE_TONE.CRITICAL}
        />
        <StatTile
          label="Overdue"
          value={meta ? (meta.overdue_count ?? 0) : "—"}
          hint="Past the remediation window"
          href={applicationFindingsHref(id, { overdue: "1" })}
          tone={STAT_TILE_TONE.DANGER}
        />
        <StatTile
          label="Posture"
          value={applicationPostureLabel({ ...application, summary })}
          tone={STAT_TILE_TONE.NEUTRAL}
        />
      </div>
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <SectionCard
          title="Findings by category"
          description="Open findings of this application per security category."
        >
          {meta ? (
            <CategoryList applicationId={id} meta={meta} />
          ) : (
            <ErrorMessage />
          )}
        </SectionCard>
        <SectionCard
          title="Findings by priority"
          description="P0 and P1 first: exploited or exposed issues."
        >
          {meta ? (
            <PriorityList applicationId={id} meta={meta} />
          ) : (
            <ErrorMessage />
          )}
        </SectionCard>
      </div>
      <SectionCard
        title="Last scan"
        actions={
          <Button asChild variant="ghost" size="sm">
            <Link href={applicationHref(id, APPLICATION_TAB.SCANS)}>
              All scans
            </Link>
          </Button>
        }
      >
        {lastRun ? (
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <RunStatusBadge status={lastRun.attributes.status} />
            <span className="text-text-neutral-primary font-medium">
              {lastRun.attributes.target_name || lastRun.attributes.target_id}
            </span>
            <span className="text-text-neutral-secondary">
              {formatRunTime(
                lastRun.attributes.finished_at ||
                  lastRun.attributes.started_at ||
                  lastRun.attributes.inserted_at,
              )}
            </span>
          </div>
        ) : runsLoaded ? (
          <p className="text-text-neutral-secondary text-sm">
            Not scanned yet. Open a target and start a scan.
          </p>
        ) : (
          <ErrorMessage message="Scans could not be loaded. Reload the page in a moment." />
        )}
      </SectionCard>
    </div>
  );

  const targetsContent = (
    <SectionCard
      title="Targets"
      description="Each target scans this source on demand or on a schedule."
      actions={
        <Button asChild size="sm">
          <Link href={newTargetHref(id)}>
            <Plus aria-hidden="true" />
            New target
          </Link>
        </Button>
      }
    >
      <TrivyTargetList targets={application.targets} />
    </SectionCard>
  );

  const findingsContent = (
    <SectionCard
      title="Findings"
      description="Open findings of this application. Pick a category to narrow the list."
      actions={
        <Button asChild size="sm">
          <Link href={applicationFindingsHref(id)}>Open all findings</Link>
        </Button>
      }
    >
      {meta ? (
        <CategoryList applicationId={id} meta={meta} />
      ) : (
        <ErrorMessage />
      )}
    </SectionCard>
  );

  const scansContent = (
    <SectionCard
      title="Scans"
      description={`The latest ${RECENT_RUN_LIMIT} scans of this application's targets, newest first.`}
    >
      {runsLoaded ? (
        <AppSecurityRunList
          runs={runs}
          emptyMessage="No scans yet. Open a target and start a scan."
        />
      ) : (
        <ErrorMessage message="Scans could not be loaded. Reload the page in a moment." />
      )}
    </SectionCard>
  );

  return (
    <ProductPageTabs
      activeTab={activeTab}
      actions={reportsAction}
      tabs={[
        {
          value: APPLICATION_TAB.OVERVIEW,
          label: "Overview",
          href: applicationHref(id, APPLICATION_TAB.OVERVIEW),
          content: overviewContent,
        },
        {
          value: APPLICATION_TAB.TARGETS,
          label: "Targets",
          href: applicationHref(id, APPLICATION_TAB.TARGETS),
          content: targetsContent,
        },
        {
          value: APPLICATION_TAB.FINDINGS,
          label: "Findings",
          href: applicationHref(id, APPLICATION_TAB.FINDINGS),
          content: findingsContent,
        },
        {
          value: APPLICATION_TAB.SCANS,
          label: "Scans",
          href: applicationHref(id, APPLICATION_TAB.SCANS),
          content: scansContent,
        },
      ]}
    />
  );
};
