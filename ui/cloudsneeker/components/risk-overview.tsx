import { Suspense } from "react";

import {
  getReportRunData,
  listReportRuns,
} from "@/cloudsneeker/actions/reports";
import { isCloudsneekerFeatureEnabled } from "@/cloudsneeker/features";
import { responseList } from "@/cloudsneeker/lib/findings-links";
import {
  buildRiskOverview,
  hasNewerActiveRun,
  latestCompletedRun,
  reportPayloadFrom,
} from "@/cloudsneeker/lib/risk-overview";
import {
  REPORT_TYPE_ID,
  type ReportRunResource,
} from "@/cloudsneeker/types/reports";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";

import { RiskOverviewPanel } from "./risk-overview-panel";

/** Executive runs read to find the newest completed one. */
const RECENT_EXECUTIVE_RUNS = "10";

const RiskOverviewSkeleton = () => (
  <Skeleton className="h-[420px] w-full rounded-xl" />
);

const RiskOverviewSSR = async () => {
  const runsResponse = await listReportRuns({
    "filter[report_type]": REPORT_TYPE_ID.EXECUTIVE,
    sort: "-inserted_at",
    "page[size]": RECENT_EXECUTIVE_RUNS,
  });
  const runs = responseList<ReportRunResource>(runsResponse);
  const latest = latestCompletedRun(runs);
  const refreshing = hasNewerActiveRun(runs, latest);

  if (!latest) {
    return <RiskOverviewPanel model={null} refreshing={refreshing} />;
  }

  const report = reportPayloadFrom(await getReportRunData(latest.id));
  return (
    <RiskOverviewPanel
      model={report ? buildRiskOverview(report, latest.id) : null}
      refreshing={refreshing}
    />
  );
};

/**
 * Overview risk view across every product area. Rendered from the upstream
 * Overview page through one `cloudsneeker-hook` line.
 */
export const RiskOverview = () => {
  if (!isCloudsneekerFeatureEnabled("reports")) return null;
  return (
    <div className="mb-6">
      <Suspense fallback={<RiskOverviewSkeleton />}>
        <RiskOverviewSSR />
      </Suspense>
    </div>
  );
};
