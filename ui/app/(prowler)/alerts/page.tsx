import { BellRing } from "lucide-react";
import { redirect } from "next/navigation";

import { getLatestMetadataInfo } from "@/actions/findings";
import { getAllProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import { getAlert, listAlerts } from "@/app/(prowler)/alerts/_actions";
import { AlertsLighthouseContext } from "@/app/(prowler)/alerts/_components/alerts-lighthouse-context";
import { AlertsManager } from "@/app/(prowler)/alerts/_components/alerts-manager";
import { listAlertEvents } from "@/cloudsneeker/actions/alert-events"; // cloudsneeker-hook
import { AlertHistory } from "@/cloudsneeker/components/alert-history"; // cloudsneeker-hook
import { AlertsSummary } from "@/cloudsneeker/components/alerts-summary"; // cloudsneeker-hook
import { ALERTS_VIEW, AlertsTabs } from "@/cloudsneeker/components/alerts-tabs"; // cloudsneeker-hook
import { isCloudsneekerFeatureEnabled } from "@/cloudsneeker/features"; // cloudsneeker-hook
import { requestedNewAlertArea } from "@/cloudsneeker/lib/alert-areas"; // cloudsneeker-hook
import {
  ALERTS_HISTORY_TAB,
  ALERTS_TAB_PARAM,
  alertHistoryQuery,
  toAlertEvents,
} from "@/cloudsneeker/lib/alert-history"; // cloudsneeker-hook
import {
  paginationOf,
  parseListFilters,
} from "@/cloudsneeker/lib/list-filters"; // cloudsneeker-hook
import { ContentLayout } from "@/components/shadcn/content-layout";
import { createScanDetailsMapping } from "@/lib";
import { isCloud } from "@/lib/shared/env";
import type { MetaDataProps, ScanEntity, ScanProps } from "@/types";

interface AlertsPageProps {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}

const getParamValue = (
  params: Awaited<AlertsPageProps["searchParams"]>,
  key: string,
): string | undefined => {
  const value = params[key];
  return Array.isArray(value) ? value[0] : value;
};

const toAlertsSearchParams = (
  resolvedSearchParams: Awaited<AlertsPageProps["searchParams"]>,
): Record<string, string> => {
  const page = Number.parseInt(
    getParamValue(resolvedSearchParams, "page") ?? "1",
    10,
  );
  const pageSize = Number.parseInt(
    getParamValue(resolvedSearchParams, "pageSize") ?? "20",
    10,
  );
  const sort = getParamValue(resolvedSearchParams, "sort") ?? "-inserted_at";
  const search = getParamValue(resolvedSearchParams, "filter[search]") ?? "";
  const enabledFilter = getParamValue(resolvedSearchParams, "filter[enabled]");
  const triggerFilter = getParamValue(resolvedSearchParams, "filter[trigger]");

  const params: Record<string, string> = {
    "page[number]": String(page),
    "page[size]": String(pageSize),
    sort,
  };
  if (search) params["filter[search]"] = search;
  if (enabledFilter) params["filter[enabled]"] = enabledFilter;
  if (triggerFilter) params["filter[trigger]"] = triggerFilter;
  return params;
};

export default async function AlertsPage({ searchParams }: AlertsPageProps) {
  if (!isCloud() && !isCloudsneekerFeatureEnabled("alerts")) {
    redirect("/");
  }

  const resolvedSearchParams = await searchParams;

  // cloudsneeker-hook: History tab lists each firing of a rule with its status.
  if (
    isCloudsneekerFeatureEnabled("alerts") &&
    getParamValue(resolvedSearchParams, ALERTS_TAB_PARAM) === ALERTS_HISTORY_TAB
  ) {
    const historyFilters = parseListFilters(resolvedSearchParams);
    const historyResult = await listAlertEvents(
      alertHistoryQuery(historyFilters),
    );
    const historyError =
      historyResult && "error" in historyResult
        ? String(historyResult.error)
        : null;
    return (
      <ContentLayout title="Alerts" icon={<BellRing />}>
        <AlertsTabs active={ALERTS_VIEW.HISTORY} />
        <AlertHistory
          events={historyError ? [] : toAlertEvents(historyResult)}
          filters={historyFilters}
          pagination={paginationOf(historyResult, historyFilters.page)}
          loadError={historyError}
        />
      </ContentLayout>
    );
  }

  const editAlertId = getParamValue(resolvedSearchParams, "edit");
  const [result, providersData, scansData, metadataInfoData, editResult] =
    await Promise.all([
      listAlerts(toAlertsSearchParams(resolvedSearchParams)),
      getAllProviders(),
      getScans({ pageSize: 50 }),
      getLatestMetadataInfo({}),
      editAlertId ? getAlert(editAlertId) : Promise.resolve(null),
    ]);
  const hasError = result && "error" in result;
  const alerts = !hasError ? result.data : [];
  const apiMeta = !hasError ? result.meta : undefined;
  const loadError = hasError ? result.error : null;
  const uniqueRegions = metadataInfoData?.data?.attributes?.regions || [];
  const uniqueServices = metadataInfoData?.data?.attributes?.services || [];
  const uniqueResourceTypes =
    metadataInfoData?.data?.attributes?.resource_types || [];
  const uniqueCategories = metadataInfoData?.data?.attributes?.categories || [];
  const uniqueGroups = metadataInfoData?.data?.attributes?.groups || [];
  const scans = scansData && "data" in scansData ? scansData.data : [];
  const completedScans = scans?.filter(
    (scan: ScanProps) =>
      scan.attributes.state === "completed" &&
      scan.attributes.unique_resource_count > 1,
  );
  const completedScanIds =
    completedScans?.map((scan: ScanProps) => scan.id) || [];
  const scanDetails = createScanDetailsMapping(
    completedScans || [],
    providersData,
  ) as { [uid: string]: ScanEntity }[];
  const editingAlert =
    editResult && !("error" in editResult) ? editResult.data : null;
  const meta: MetaDataProps | undefined = apiMeta?.pagination
    ? {
        pagination: {
          page: apiMeta.pagination.page,
          pages: apiMeta.pagination.pages,
          count: apiMeta.pagination.count,
        },
        version: "1",
      }
    : undefined;

  return (
    <ContentLayout title="Alerts" icon={<BellRing />}>
      {/* cloudsneeker-hook: Rules and History views */}
      {isCloudsneekerFeatureEnabled("alerts") ? (
        <AlertsTabs active={ALERTS_VIEW.RULES} />
      ) : null}
      {/* cloudsneeker-hook: key figures above the alerts list */}
      <AlertsSummary
        alerts={alerts}
        totalCount={apiMeta?.pagination?.count}
        unavailable={Boolean(hasError)}
      />
      {!hasError ? (
        <AlertsLighthouseContext
          totalCount={apiMeta?.pagination?.count ?? alerts.length}
          editingAlert={editingAlert}
        />
      ) : null}
      <AlertsManager
        alerts={alerts}
        meta={meta}
        loadError={loadError}
        providers={providersData?.data || []}
        completedScanIds={completedScanIds}
        scanDetails={scanDetails}
        uniqueRegions={uniqueRegions}
        uniqueServices={uniqueServices}
        uniqueResourceTypes={uniqueResourceTypes}
        uniqueCategories={uniqueCategories}
        uniqueGroups={uniqueGroups}
        initialEditingAlert={editingAlert}
        initialNewArea={requestedNewAlertArea(resolvedSearchParams)}
      />
    </ContentLayout>
  );
}
