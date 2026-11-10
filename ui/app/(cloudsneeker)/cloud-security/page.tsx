import { Cloud } from "lucide-react";
import { Suspense } from "react";

import { getAllProviderGroups } from "@/actions/manage-groups/manage-groups";
import { getAllProviders } from "@/actions/providers";
import { OverviewBanner } from "@/app/(prowler)/_overview/_components/overview-banner";
import { OverviewProviderContext } from "@/app/(prowler)/_overview/_components/overview-provider-context";
import { getLighthouseOverviewBannerHref } from "@/app/(prowler)/_overview/_lib/lighthouse-banner";
import { OVERVIEW_BANNER_VARIANT } from "@/app/(prowler)/_overview/_lib/overview-banner";
import {
  AttackSurfaceSkeleton,
  AttackSurfaceSSR,
} from "@/app/(prowler)/_overview/attack-surface";
import { CheckFindingsSSR } from "@/app/(prowler)/_overview/check-findings";
import { GraphsTabsWrapper } from "@/app/(prowler)/_overview/graphs-tabs/graphs-tabs-wrapper";
import { RiskPipelineViewSkeleton } from "@/app/(prowler)/_overview/graphs-tabs/risk-pipeline-view";
import {
  ResourcesInventorySkeleton,
  ResourcesInventorySSR,
} from "@/app/(prowler)/_overview/resources-inventory";
import {
  RiskSeverityChartSkeleton,
  RiskSeverityChartSSR,
} from "@/app/(prowler)/_overview/risk-severity";
import {
  FindingSeverityOverTimeSkeleton,
  FindingSeverityOverTimeSSR,
} from "@/app/(prowler)/_overview/severity-over-time/finding-severity-over-time.ssr";
import { StatusChartSkeleton } from "@/app/(prowler)/_overview/status-chart";
import {
  ThreatScoreSkeleton,
  ThreatScoreSSR,
} from "@/app/(prowler)/_overview/threat-score";
import {
  ComplianceWatchlistSSR,
  ServiceWatchlistSSR,
  WatchlistCardSkeleton,
} from "@/app/(prowler)/_overview/watchlist";
import { getLighthouseV2Configurations } from "@/app/(prowler)/lighthouse/_actions";
import { BRAND } from "@/cloudsneeker/brand";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { ProviderAccountSelectors } from "@/components/filters/provider-account-selectors";
import { ProviderGroupSelector } from "@/components/filters/provider-group-selector";
import {
  APP_SIDEBAR_MODE,
  AppSidebarModeSync,
} from "@/components/layout/app-sidebar";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { isCloud } from "@/lib/shared/env";
import type { SearchParamsProps } from "@/types";

/**
 * Cloud Security dashboard: the cloud posture widgets that used to fill the
 * Overview (threat score, check findings, severity, resources, watchlists,
 * attack surface, findings over time, risk pipeline). Same upstream
 * components and data; the Overview now summarises every product area.
 * After an upstream merge, mirror widget changes from `app/(prowler)/page.tsx`.
 */
export default async function CloudSecurityPage({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  const resolvedSearchParams = await searchParams;
  const [providersData, providerGroupsData, lighthouseBannerHref] =
    await Promise.all([
      getAllProviders(),
      getAllProviderGroups(),
      getLighthouseOverviewBannerHref(isCloud(), getLighthouseV2Configurations),
    ]);

  return (
    <ContentLayout title={BRAND.cloudSecurityName} icon={<Cloud />}>
      <AppSidebarModeSync mode={APP_SIDEBAR_MODE.BROWSE} />
      <OverviewProviderContext
        searchParams={resolvedSearchParams}
        providers={providersData?.data ?? []}
        groups={providerGroupsData?.data ?? []}
      />
      <PageHeader description="Cloud posture across your accounts: threat score, failed checks, resources, compliance watchlist, attack surface and trends. Filter by provider, account or group." />

      <div className="mb-6 grid grid-cols-1 gap-6 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
        <ProviderAccountSelectors providers={providersData?.data ?? []} />
        <ProviderGroupSelector groups={providerGroupsData?.data ?? []} />
      </div>

      <div className="flex flex-col gap-6 lg:flex-row lg:flex-wrap lg:items-stretch">
        <Suspense fallback={<ThreatScoreSkeleton />}>
          <ThreatScoreSSR searchParams={resolvedSearchParams} />
        </Suspense>

        <Suspense fallback={<StatusChartSkeleton />}>
          <CheckFindingsSSR searchParams={resolvedSearchParams} />
        </Suspense>

        <Suspense fallback={<RiskSeverityChartSkeleton />}>
          <RiskSeverityChartSSR searchParams={resolvedSearchParams} />
        </Suspense>
      </div>

      <div className="mt-6">
        <Suspense fallback={<ResourcesInventorySkeleton />}>
          <ResourcesInventorySSR searchParams={resolvedSearchParams} />
        </Suspense>
      </div>

      <div className="mt-6 flex flex-col gap-6 xl:flex-row">
        <div className="flex min-w-0 flex-col gap-6 overflow-hidden sm:flex-row sm:items-stretch xl:w-[312px] xl:shrink-0 xl:flex-col">
          <div className="min-w-0 sm:flex-1 xl:flex-none sm:[&>*]:h-full xl:[&>*]:h-auto">
            <Suspense fallback={<WatchlistCardSkeleton />}>
              <ComplianceWatchlistSSR searchParams={resolvedSearchParams} />
            </Suspense>
          </div>
          <div className="min-w-0 sm:flex-1 xl:flex-auto [&>*]:h-full">
            <Suspense fallback={<WatchlistCardSkeleton />}>
              <ServiceWatchlistSSR searchParams={resolvedSearchParams} />
            </Suspense>
          </div>
        </div>

        <div className="flex flex-1 flex-col gap-6">
          <Suspense fallback={<AttackSurfaceSkeleton />}>
            <AttackSurfaceSSR searchParams={resolvedSearchParams} />
          </Suspense>
          <Suspense fallback={<FindingSeverityOverTimeSkeleton />}>
            <FindingSeverityOverTimeSSR searchParams={resolvedSearchParams} />
          </Suspense>
        </div>
      </div>

      <div className="mt-6">
        <Suspense fallback={<RiskPipelineViewSkeleton />}>
          <GraphsTabsWrapper searchParams={resolvedSearchParams} />
        </Suspense>
      </div>

      {lighthouseBannerHref ? (
        <div className="mt-6">
          <OverviewBanner
            variant={OVERVIEW_BANNER_VARIANT.LIGHTHOUSE}
            href={lighthouseBannerHref}
          />
        </div>
      ) : null}
    </ContentLayout>
  );
}
