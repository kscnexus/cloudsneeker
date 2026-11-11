import { Settings2 } from "lucide-react";

import {
  getAppSecEngine,
  getAppSecSettings,
  listAppSecPolicies,
} from "@/cloudsneeker/actions/appsec";
import { AppSecPoliciesManager } from "@/cloudsneeker/components/appsec-policies-manager";
import { AppSecSettingsForm } from "@/cloudsneeker/components/appsec-settings-form";
import {
  CountBars,
  LoadError,
  TABLE_CLASS,
  TABLE_WRAPPER_CLASS,
  TD_CLASS,
  TD_PRIMARY_CLASS,
  TH_CLASS,
} from "@/cloudsneeker/components/appsec-ui";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { runStatusLabel } from "@/cloudsneeker/components/run-status-badge";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { StatTile } from "@/cloudsneeker/components/stat-tile";
import {
  APPSEC_FEATURE_STATUS_TONE,
  APPSEC_SEGMENT,
  attributesOf,
  formatAppSecDate,
} from "@/cloudsneeker/lib/appsec";
import {
  canManageScans,
  loadCapabilities,
  loadProfileOptions,
} from "@/cloudsneeker/lib/appsec-server";
import { responseList } from "@/cloudsneeker/lib/findings-links";
import { appSecurityHref } from "@/cloudsneeker/routes";
import {
  APPSEC_FEATURE_STATUS,
  type AppSecEngineStatus,
  type AppSecFeatureStatus,
  type AppSecPolicyAttributes,
  type AppSecResource,
  type AppSecSettings,
} from "@/cloudsneeker/types/appsec";
import { Badge } from "@/components/shadcn/badge/badge";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { cn } from "@/lib/utils";

const STATUS_VARIANT: Record<string, "success" | "warning" | "error" | "tag"> =
  {
    success: "success",
    warning: "warning",
    danger: "error",
    neutral: "tag",
  };

const LIMIT_LABEL: Record<string, string> = {
  default_timeout_seconds: "Default scan timeout (seconds)",
  max_active_runs_per_target: "Concurrent scans per asset",
  max_active_runs_per_tenant: "Concurrent scans per organization",
  max_queued_runs_per_tenant: "Queued scans per organization",
  max_attempts: "Attempts per scan (with retries)",
  max_report_bytes: "Largest scan report (bytes)",
  max_archive_bytes: "Largest uploaded archive (bytes)",
  max_extracted_bytes: "Largest extracted archive (bytes)",
  max_extracted_files: "Most files in an archive",
  max_images_per_run: "Images per scan",
};

const text = (value: unknown): string =>
  typeof value === "string" || typeof value === "number" ? String(value) : "";

export default async function AppSecuritySettingsPage() {
  const [
    capabilities,
    engineResponse,
    settingsResponse,
    policiesResponse,
    profiles,
    canManage,
  ] = await Promise.all([
    loadCapabilities(),
    getAppSecEngine(),
    getAppSecSettings(),
    listAppSecPolicies({ "page[size]": "100" }),
    loadProfileOptions(),
    canManageScans(),
  ]);
  const engine = attributesOf<AppSecEngineStatus>(engineResponse);
  const settings = attributesOf<AppSecSettings>(settingsResponse);
  const policies =
    responseList<AppSecResource<AppSecPolicyAttributes>>(policiesResponse);

  if (!capabilities || !engine || !settings) {
    return (
      <ContentLayout title="Scanning settings" icon={<Settings2 />}>
        <LoadError
          title="Settings"
          what="Settings"
          reloadHref={appSecurityHref(APPSEC_SEGMENT.SETTINGS)}
        />
      </ContentLayout>
    );
  }

  const database = engine.vulnerability_database;
  const counts = capabilities.features.reduce<Record<string, number>>(
    (totals, feature) => ({
      ...totals,
      [feature.status]: (totals[feature.status] ?? 0) + 1,
    }),
    {},
  );
  const scannerLabel = (id: string) =>
    capabilities.scanners.find((scanner) => scanner.id === id)?.label ?? id;

  return (
    <ContentLayout title="Scanning settings" icon={<Settings2 />}>
      <PageHeader description="Scan engine status, what it supports for each target type, the policies applied to scans, and how findings are prioritized and retained. Engine limits are set by the platform operator and are read only here." />
      <div className="flex flex-col gap-6">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          <StatTile
            label="Scan engine"
            value={
              engine.engine.available ? engine.engine.version : "Unavailable"
            }
            tone={
              !engine.engine.available
                ? "danger"
                : engine.engine.matches_pin
                  ? "success"
                  : "warning"
            }
            hint={
              engine.engine.available
                ? engine.engine.matches_pin
                  ? "Matches the verified release"
                  : `Expected ${engine.engine.pinned_version}`
                : engine.engine.error
            }
          />
          <StatTile
            label="Vulnerability data"
            value={text(database.status) || "Unknown"}
            hint={
              text(database.published_at)
                ? `Published ${formatAppSecDate(text(database.published_at))}`
                : undefined
            }
          />
          <StatTile label="Queued scans" value={engine.queue.pending} />
          <StatTile label="Running scans" value={engine.queue.running} />
          <StatTile
            label="Failed, 7 days"
            value={engine.last_7_days.by_status.failed ?? 0}
            tone={
              (engine.last_7_days.by_status.failed ?? 0) > 0
                ? "warning"
                : "neutral"
            }
            hint={`${engine.last_7_days.total} scans`}
          />
        </div>

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
          <SectionCard
            title="Scans, last 7 days"
            description="Outcome of every scan started in the period."
          >
            <CountBars
              items={Object.entries(engine.last_7_days.by_status).map(
                ([status, count]) => ({
                  key: status,
                  label: runStatusLabel(status),
                  count,
                }),
              )}
            />
          </SectionCard>
          <SectionCard
            title="Failure reasons"
            description="Why failed scans stopped."
          >
            {Object.keys(engine.last_7_days.by_failure).length === 0 ? (
              <p className="text-text-neutral-secondary text-sm">
                No failed scans in the period.
              </p>
            ) : (
              <CountBars
                items={Object.entries(engine.last_7_days.by_failure).map(
                  ([reason, count]) => ({
                    key: reason || "unknown",
                    label: (reason || "unknown").replace(/_/g, " "),
                    count,
                    className: "bg-bg-fail",
                  }),
                )}
              />
            )}
          </SectionCard>
          <SectionCard
            title="Execution limits"
            description="Platform settings; not editable per organization."
          >
            <dl className="flex flex-col gap-1 text-sm">
              {Object.entries(engine.limits).map(([key, value]) => (
                <div key={key} className="flex justify-between gap-3">
                  <dt className="text-text-neutral-secondary">
                    {LIMIT_LABEL[key] ?? key}
                  </dt>
                  <dd className="text-text-neutral-primary tabular-nums">
                    {value.toLocaleString("en-US")}
                  </dd>
                </div>
              ))}
            </dl>
          </SectionCard>
        </div>

        <AppSecPoliciesManager policies={policies} canManage={canManage} />

        <SectionCard
          title="Prioritization, deadlines and retention"
          description="Organization preferences. They never change what the scanner reports."
        >
          {canManage ? (
            <AppSecSettingsForm
              settings={settings}
              targets={capabilities.targets}
              profiles={profiles}
            />
          ) : (
            <p className="text-text-neutral-secondary text-sm">
              Changing these settings needs the manage scans permission.
            </p>
          )}
        </SectionCard>

        <SectionCard
          title="Supported targets and scanners"
          description={`What scan engine ${capabilities.engine_version} accepts for each target type. Profiles and targets can only use these combinations.`}
        >
          <div className={TABLE_WRAPPER_CLASS}>
            <table className={TABLE_CLASS}>
              <thead>
                <tr>
                  {[
                    "Target type",
                    "Scanners",
                    "Default",
                    "Exports",
                    "Notes",
                  ].map((heading) => (
                    <th key={heading} scope="col" className={TH_CLASS}>
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {capabilities.targets.map((target) => (
                  <tr key={target.id}>
                    <td className={TD_PRIMARY_CLASS}>
                      {target.label}
                      {target.experimental ? (
                        <>
                          {" "}
                          <Badge variant="warning">Experimental</Badge>
                        </>
                      ) : null}
                    </td>
                    <td className={TD_CLASS}>
                      {target.scanners.map(scannerLabel).join(", ")}
                    </td>
                    <td className={TD_CLASS}>
                      {target.default_scanners.map(scannerLabel).join(", ")}
                    </td>
                    <td className={cn(TD_CLASS, "text-xs")}>
                      {target.export_formats.join(", ")}
                    </td>
                    <td className={cn(TD_CLASS, "max-w-md text-xs")}>
                      {target.notes.join(" ")}
                    </td>
                  </tr>
                ))}
                {capabilities.other_engine_targets.map((target) => (
                  <tr key={target.id}>
                    <td className={TD_PRIMARY_CLASS}>{target.label}</td>
                    <td className={TD_CLASS} colSpan={3}>
                      Code analysis rules
                    </td>
                    <td className={cn(TD_CLASS, "text-xs")}>
                      Runs on a separate code analysis engine.
                    </td>
                  </tr>
                ))}
                {capabilities.unavailable_targets.map((target) => (
                  <tr key={target.id}>
                    <td className={TD_PRIMARY_CLASS}>
                      {target.label} <Badge variant="tag">Not offered</Badge>
                    </td>
                    <td className={cn(TD_CLASS, "text-xs")} colSpan={4}>
                      {target.reason}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SectionCard>

        <SectionCard
          title="Feature coverage"
          description={`${counts[APPSEC_FEATURE_STATUS.IMPLEMENTED] ?? 0} implemented, ${counts[APPSEC_FEATURE_STATUS.PARTIAL] ?? 0} partially implemented, ${counts[APPSEC_FEATURE_STATUS.MISSING] ?? 0} missing, ${counts[APPSEC_FEATURE_STATUS.UNSUPPORTED] ?? 0} unsupported by the engine, ${counts[APPSEC_FEATURE_STATUS.NOT_APPLICABLE] ?? 0} not applicable.`}
        >
          <div className={TABLE_WRAPPER_CLASS}>
            <table className={TABLE_CLASS}>
              <thead>
                <tr>
                  {["Area", "Capability", "Status", "Detail"].map((heading) => (
                    <th key={heading} scope="col" className={TH_CLASS}>
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {capabilities.features.map((feature) => (
                  <tr key={`${feature.area}:${feature.feature}`}>
                    <td className={cn(TD_CLASS, "whitespace-nowrap")}>
                      {feature.area}
                    </td>
                    <td className={cn(TD_PRIMARY_CLASS, "max-w-xs")}>
                      {feature.feature}
                    </td>
                    <td className={cn(TD_CLASS, "whitespace-nowrap")}>
                      <Badge
                        variant={
                          STATUS_VARIANT[
                            APPSEC_FEATURE_STATUS_TONE[
                              feature.status as AppSecFeatureStatus
                            ]
                          ] ?? "tag"
                        }
                      >
                        {feature.status_label}
                      </Badge>
                    </td>
                    <td className={cn(TD_CLASS, "max-w-xl text-xs")}>
                      {feature.detail}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SectionCard>
      </div>
    </ContentLayout>
  );
}
