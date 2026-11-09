// Server-side readers for the product dashboards. Each one calls an existing
// API (area findings, compliance watchlist, findings severity overview,
// providers, scans, application scans, policy dry-runs) and returns `null`
// when the request fails, so a widget shows an error instead of a zero.

import "server-only";

import {
  adaptComplianceWatchlistResponse,
  getComplianceWatchlist,
} from "@/actions/overview/compliance-watchlist";
import { getFindingsBySeverity } from "@/actions/overview/findings/findings";
import { getProvidersOverview } from "@/actions/overview/providers/providers";
import { getProviders } from "@/actions/providers/providers";
import { getScans } from "@/actions/scans/scans";
import { listCustodianRuns } from "@/cloudsneeker/actions/custodian";
import { listAreaFindings } from "@/cloudsneeker/actions/finding-triage";
import { listTrivyRuns, listTrivyTargets } from "@/cloudsneeker/actions/trivy";
import type { SeverityBreakdownItem } from "@/cloudsneeker/components/severity-breakdown";
import { areaFindingsPageHref } from "@/cloudsneeker/lib/area-findings";
import {
  ACTIVITY_KIND,
  type ActivityItem,
  type ComplianceFrameworkRow,
  REMEDIATION_STATUS_ORDER,
  toActivityState,
} from "@/cloudsneeker/lib/dashboards";
import {
  isListResponse,
  openFindingsHref,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import { appSecurityHref, governanceHref } from "@/cloudsneeker/routes";
import type {
  AreaFindingResource,
  FindingArea,
} from "@/cloudsneeker/types/area-findings";
import type { CustodianRunResource } from "@/cloudsneeker/types/custodian";
import {
  REPORT_SEVERITY_ORDER,
  type ReportSeverity,
} from "@/cloudsneeker/types/reports";
import type {
  TrivyRunResource,
  TrivyTargetResource,
} from "@/cloudsneeker/types/trivy";
import type { FindingTriageStatus } from "@/types/findings-triage";
import type { ScanProps } from "@/types/scans";

/** Runs read for counts and trends; enough for a month of daily scans. */
export const DASHBOARD_RUN_PAGE_SIZE = "100";

/** Open findings in an area matching `filters` (count only), or null. */
export const countAreaFindings = async (
  area: FindingArea,
  filters: Record<string, string> = {},
): Promise<number | null> => {
  const response: unknown = await listAreaFindings({
    "filter[area]": area,
    "page[size]": "1",
    ...filters,
  });
  return isListResponse(response) ? responseCount(response) : null;
};

/** Open findings per severity in an area, each linking to the filtered list. */
export const loadAreaSeverity = async (
  area: FindingArea,
): Promise<SeverityBreakdownItem[] | null> => {
  const counts = await Promise.all(
    REPORT_SEVERITY_ORDER.map((severity) =>
      countAreaFindings(area, { "filter[severity__in]": severity }),
    ),
  );
  if (counts.some((count) => count === null)) return null;
  return REPORT_SEVERITY_ORDER.map((severity: ReportSeverity, index) => ({
    severity,
    count: counts[index] ?? 0,
    href: areaFindingsPageHref(area, { severities: [severity] }),
  }));
};

/** Open findings per triage state in an area (remediation progress). */
export const loadAreaTriageCounts = async (
  area: FindingArea,
): Promise<Partial<Record<FindingTriageStatus, number | null>>> => {
  const counts = await Promise.all(
    REMEDIATION_STATUS_ORDER.map((status) =>
      countAreaFindings(area, { "filter[triage_status__in]": status }),
    ),
  );
  return Object.fromEntries(
    REMEDIATION_STATUS_ORDER.map((status, index) => [status, counts[index]]),
  );
};

/** Failed cloud findings per severity (latest scans), or null. */
export const loadCloudSeverity = async (): Promise<
  SeverityBreakdownItem[] | null
> => {
  // Same filter as the Cloud Security severity chart: failed findings only.
  const response = await getFindingsBySeverity({
    filters: { "filter[status]": "FAIL" },
  });
  const attributes =
    response && "data" in response
      ? (response.data as { attributes?: Record<string, number> } | undefined)
          ?.attributes
      : undefined;
  if (!attributes) return null;
  return REPORT_SEVERITY_ORDER.map((severity) => ({
    severity,
    count: Number(attributes[severity] ?? 0) || 0,
    href: openFindingsHref({ "filter[severity__in]": severity }),
  }));
};

/** Every framework of the latest scans, with its requirement counts. */
export const loadComplianceFrameworks = async (): Promise<
  ComplianceFrameworkRow[] | null
> => {
  const response = await getComplianceWatchlist({ inWatchlist: false });
  if (!response || !("data" in response) || !Array.isArray(response.data)) {
    return null;
  }
  return (
    adaptComplianceWatchlistResponse(response)
      // ThreatScore is a score of its own, not a framework.
      .filter(
        (item) => !item.complianceId.toLowerCase().includes("threatscore"),
      )
      .map((item) => ({
        id: item.complianceId,
        label: item.label,
        passed: Number(item.requirementsPassed) || 0,
        failed: Number(item.requirementsFailed) || 0,
        manual: Number(item.requirementsManual) || 0,
        total: Number(item.totalRequirements) || 0,
        score: item.score,
      }))
  );
};

export interface ProviderCounts {
  total: number;
  connected: number;
  byType: { type: string; count: number }[];
}

/** Connected cloud accounts and code sources, or null. */
export const loadProviderCounts = async (): Promise<ProviderCounts | null> => {
  const response = await getProviders({ pageSize: 100 });
  if (!response || !Array.isArray(response.data)) return null;
  const byType = new Map<string, number>();
  let connected = 0;
  for (const provider of response.data) {
    const type = provider.attributes.provider;
    byType.set(type, (byType.get(type) ?? 0) + 1);
    if (provider.attributes.connection?.connected) connected += 1;
  }
  return {
    total: responseCount(response) ?? response.data.length,
    connected,
    byType: Array.from(byType.entries())
      .map(([type, count]) => ({ type, count }))
      .sort((left, right) => right.count - left.count),
  };
};

export const loadAppTargets = async (): Promise<
  TrivyTargetResource[] | null
> => {
  const response: unknown = await listTrivyTargets({
    "page[size]": "100",
    sort: "-inserted_at",
  });
  return isListResponse(response)
    ? responseList<TrivyTargetResource>(response)
    : null;
};

export const loadAppRuns = async (): Promise<TrivyRunResource[] | null> => {
  const response: unknown = await listTrivyRuns({
    "page[size]": DASHBOARD_RUN_PAGE_SIZE,
    sort: "-inserted_at",
  });
  return isListResponse(response)
    ? responseList<TrivyRunResource>(response)
    : null;
};

export const loadPolicyRuns = async (): Promise<
  CustodianRunResource[] | null
> => {
  const response: unknown = await listCustodianRuns({
    "page[size]": DASHBOARD_RUN_PAGE_SIZE,
    sort: "-inserted_at",
  });
  return isListResponse(response)
    ? responseList<CustodianRunResource>(response)
    : null;
};

/** Newest cloud scans, or null. */
export const loadCloudScans = async (
  pageSize = 10,
): Promise<ScanProps[] | null> => {
  const response: unknown = await getScans({
    page: 1,
    pageSize,
    sort: "-inserted_at",
  });
  return isListResponse(response) ? responseList<ScanProps>(response) : null;
};

export const cloudScanActivity = (scans: ScanProps[]): ActivityItem[] =>
  scans.map((scan) => {
    const state = toActivityState(scan.attributes.state);
    return {
      id: `scan-${scan.id}`,
      kind: ACTIVITY_KIND.CLOUD_SCAN,
      title: scan.attributes.name || "Cloud scan",
      state,
      at: scan.attributes.inserted_at,
      href:
        state === "completed"
          ? openFindingsHref({ "filter[scan__in]": scan.id })
          : "/scans",
      count: null,
    };
  });

export const appScanActivity = (runs: TrivyRunResource[]): ActivityItem[] =>
  runs.map((run) => ({
    id: `app-${run.id}`,
    kind: ACTIVITY_KIND.APP_SCAN,
    title: run.attributes.target_name || "Application scan",
    state: toActivityState(run.attributes.status),
    at: run.attributes.inserted_at ?? "",
    href: appSecurityHref(run.attributes.target_id, "runs", run.id),
    count:
      run.attributes.summary?.finding_count === undefined ||
      run.attributes.summary?.finding_count === null
        ? null
        : Number(run.attributes.summary.finding_count),
  }));

export const policyRunActivity = (
  runs: CustodianRunResource[],
): ActivityItem[] =>
  runs.map((run) => ({
    id: `policy-${run.id}`,
    kind: ACTIVITY_KIND.POLICY_RUN,
    title: run.attributes.policy_name || "Policy dry-run",
    state: toActivityState(run.attributes.status),
    at: run.attributes.inserted_at ?? "",
    href: governanceHref(run.attributes.policy_id, "runs", run.id),
    count:
      run.attributes.summary?.resource_count === undefined
        ? null
        : Number(run.attributes.summary.resource_count),
  }));

export interface ProviderFindingRow {
  /** Provider type, e.g. `aws`. */
  type: string;
  pass: number;
  fail: number;
  resources: number;
}

/** Passed and failed checks per cloud provider type (latest scans), or null. */
export const loadProviderFindings = async (): Promise<
  ProviderFindingRow[] | null
> => {
  const response: unknown = await getProvidersOverview({});
  if (!isListResponse(response)) return null;
  return responseList<{
    id: string;
    attributes?: {
      findings?: { pass?: number; fail?: number };
      resources?: { total?: number };
    };
  }>(response)
    .map((row) => ({
      type: row.id,
      pass: Number(row.attributes?.findings?.pass ?? 0) || 0,
      fail: Number(row.attributes?.findings?.fail ?? 0) || 0,
      resources: Number(row.attributes?.resources?.total ?? 0) || 0,
    }))
    .sort((left, right) => right.fail - left.fail);
};

/** Open critical findings in an area, newest sighting first, or null. */
export const loadCriticalFindings = async (
  area: FindingArea,
  limit: number,
): Promise<AreaFindingResource[] | null> => {
  const response: unknown = await listAreaFindings({
    "filter[area]": area,
    "filter[severity__in]": "critical",
    "page[size]": String(limit),
    sort: "-last_seen_at",
  });
  return isListResponse(response)
    ? responseList<AreaFindingResource>(response)
    : null;
};
