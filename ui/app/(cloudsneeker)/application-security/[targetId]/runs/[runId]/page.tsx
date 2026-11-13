import { Download, ScanSearch } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import { getTrivyRun } from "@/cloudsneeker/actions/trivy";
import { BRAND } from "@/cloudsneeker/brand";
import { AppSecCancelScanButton } from "@/cloudsneeker/components/appsec-cancel-scan-button";
import { CountBars } from "@/cloudsneeker/components/appsec-ui";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { RunStatusBadge } from "@/cloudsneeker/components/run-status-badge";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { StatTile } from "@/cloudsneeker/components/stat-tile";
import {
  APPSEC_DOWNLOAD_KIND,
  APPSEC_SEGMENT,
  appSecCategoryLabel,
  appSecDownloadHref,
  appSecFindingsHref,
  appSecSbomHref,
  formatAppSecDate,
} from "@/cloudsneeker/lib/appsec";
import {
  canManageScans,
  loadCapabilities,
} from "@/cloudsneeker/lib/appsec-server";
import {
  findingsHrefForScan,
  labelForTrivyMode,
  labelForTrivyScanner,
} from "@/cloudsneeker/lib/trivy-modes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import {
  TRIVY_RUN_STATUS,
  type TrivyRunResource,
} from "@/cloudsneeker/types/trivy";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";

interface TrivyRunDetailPageProps {
  params: Promise<{ targetId: string; runId: string }>;
}

const EXPORT_LABEL: Record<string, string> = {
  json: "Report (JSON)",
  sarif: "SARIF",
  cyclonedx: "CycloneDX",
  "spdx-json": "SPDX",
};

const FAILURE_LABEL: Record<string, string> = {
  database: "Vulnerability data download",
  timeout: "Time limit",
  auth: "Credentials rejected",
  not_found: "Source not found",
  network: "Network",
  input: "Scan input",
  resources: "Worker resources",
  output: "Unreadable report",
  cancelled: "Cancelled",
  engine: "Scanner error",
};

const duration = (milliseconds: number | null | undefined): string => {
  if (!milliseconds) return "–";
  const seconds = Math.round(milliseconds / 1000);
  return seconds < 60
    ? `${seconds} s`
    : `${Math.floor(seconds / 60)} min ${seconds % 60} s`;
};

const optionValue = (value: unknown): string =>
  Array.isArray(value) ? value.join(", ") : String(value);

export default async function TrivyRunDetailPage({
  params,
}: TrivyRunDetailPageProps) {
  const { targetId, runId } = await params;
  const [runResponse, capabilities, canManage] = await Promise.all([
    getTrivyRun(runId),
    loadCapabilities(),
    canManageScans(),
  ]);

  if (
    !runResponse ||
    ("error" in runResponse && runResponse.error) ||
    !runResponse.data ||
    Array.isArray(runResponse.data)
  ) {
    notFound();
  }

  const run = runResponse.data as TrivyRunResource;
  const attributes = run.attributes;
  const mode = attributes.target_mode || attributes.summary?.mode || "";
  const scanId = attributes.scan_id || attributes.summary?.scan_id;
  const active =
    attributes.status === TRIVY_RUN_STATUS.PENDING ||
    attributes.status === TRIVY_RUN_STATUS.RUNNING;
  const stats = attributes.stats ?? {};
  const lifecycle = stats.lifecycle;
  const coverage = attributes.coverage;
  const options = attributes.options ?? {};
  const scanners = Array.isArray(options.scanners)
    ? (options.scanners as string[])
    : [];
  const exportFormats = attributes.has_artifact
    ? (capabilities?.targets.find((target) => target.id === mode)
        ?.export_formats ?? ["json"])
    : [];
  const profileName =
    capabilities?.builtin_profiles.find(
      (profile) => profile.ref === attributes.profile_ref,
    )?.name ?? (attributes.profile_ref ? "Custom profile" : "");
  const warnings = Array.isArray(attributes.output?.warnings)
    ? (attributes.output.warnings as string[])
    : [];
  const sbomId = attributes.summary?.sbom_id;
  const database = attributes.database ?? {};

  return (
    <ContentLayout
      title={attributes.target_name || `${BRAND.appSecurityName} scan`}
      icon={<ScanSearch />}
    >
      <PageHeader
        meta={[
          {
            label: "Status",
            value: <RunStatusBadge status={attributes.status} />,
          },
          { label: "Trigger", value: attributes.trigger },
          { label: "Target type", value: labelForTrivyMode(mode) },
          ...(attributes.branch
            ? [{ label: "Branch", value: attributes.branch }]
            : []),
          { label: "Started", value: formatAppSecDate(attributes.started_at) },
          { label: "Duration", value: duration(attributes.duration_ms) },
          ...(attributes.engine_version
            ? [
                {
                  label: "Scan engine",
                  value: `${attributes.engine || "scanner"} ${attributes.engine_version}`,
                },
              ]
            : []),
          ...(profileName ? [{ label: "Profile", value: profileName }] : []),
        ]}
        actions={
          <>
            <Button asChild variant="ghost" size="sm">
              <Link href={appSecurityHref(targetId)}>Back to target</Link>
            </Button>
            {active && canManage ? (
              <AppSecCancelScanButton runId={runId} />
            ) : null}
            {attributes.status === TRIVY_RUN_STATUS.COMPLETED ? (
              <Button asChild size="sm">
                <Link
                  href={
                    lifecycle
                      ? appSecFindingsHref(APPSEC_SEGMENT.FINDINGS, {
                          target: targetId,
                        })
                      : scanId
                        ? findingsHrefForScan(scanId)
                        : appSecurityHref(APPSEC_SEGMENT.FINDINGS)
                  }
                >
                  Open findings
                </Link>
              </Button>
            ) : null}
          </>
        }
      >
        {active ? (
          <p className="text-text-neutral-secondary text-sm">
            {attributes.cancel_requested_at
              ? "Cancellation requested; the scan stops within a few seconds."
              : "The scan is in progress. Reload the page to update."}
          </p>
        ) : null}
      </PageHeader>

      <div className="flex flex-col gap-6">
        {attributes.error ? (
          <SectionCard
            title={
              attributes.status === TRIVY_RUN_STATUS.CANCELLED
                ? "Scan cancelled"
                : "Scan failed"
            }
            description={
              FAILURE_LABEL[attributes.error_class ?? ""] ??
              attributes.error_class
            }
          >
            <p role="alert" className="text-text-error-primary text-sm">
              {attributes.error}
            </p>
            <dl className="grid grid-cols-2 gap-3 text-sm md:grid-cols-4">
              <div>
                <dt className="text-text-neutral-tertiary text-xs">
                  Exit status
                </dt>
                <dd className="tabular-nums">{attributes.exit_code ?? "–"}</dd>
              </div>
              <div>
                <dt className="text-text-neutral-tertiary text-xs">Attempts</dt>
                <dd className="tabular-nums">{attributes.attempts ?? 0}</dd>
              </div>
            </dl>
          </SectionCard>
        ) : null}

        {lifecycle ? (
          <div className="grid grid-cols-2 gap-3 md:grid-cols-6">
            <StatTile
              label="Reported"
              value={stats.total ?? 0}
              hint={`${stats.suppressed ?? 0} suppressed`}
            />
            <StatTile label="New" value={lifecycle.new ?? 0} tone="info" />
            <StatTile label="Still open" value={lifecycle.open ?? 0} />
            <StatTile
              label="Reopened"
              value={lifecycle.reopened ?? 0}
              tone="danger"
            />
            <StatTile
              label="Fixed"
              value={lifecycle.fixed ?? 0}
              tone="success"
            />
            <StatTile
              label="Components"
              value={stats.components ?? 0}
              href={sbomId ? appSecSbomHref(sbomId) : undefined}
              hint={sbomId ? "Open the SBOM" : undefined}
            />
          </div>
        ) : null}

        <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
          {stats.by_category && Object.keys(stats.by_category).length > 0 ? (
            <SectionCard
              title="Findings by category"
              description="Reported by this scan, not counting suppressed findings."
            >
              <CountBars
                items={Object.entries(stats.by_category).map(
                  ([category, counts]) => ({
                    key: category,
                    label: appSecCategoryLabel(category),
                    count: counts.total ?? 0,
                  }),
                )}
              />
              {stats.passed_checks ? (
                <p className="text-text-neutral-tertiary text-xs">
                  {stats.passed_checks} configuration check(s) passed.
                </p>
              ) : null}
            </SectionCard>
          ) : null}

          {coverage ? (
            <SectionCard
              title="Coverage"
              description="What this scan could report. A finding is marked fixed only when a complete scan that covers it no longer reports it."
            >
              <dl className="flex flex-col gap-2 text-sm">
                <div>
                  <dt className="text-text-neutral-tertiary text-xs">
                    Scanners run
                  </dt>
                  <dd>
                    {scanners.length > 0
                      ? scanners.map(labelForTrivyScanner).join(", ")
                      : (coverage.categories ?? [])
                          .map(appSecCategoryLabel)
                          .join(", ")}
                  </dd>
                </div>
                <div>
                  <dt className="text-text-neutral-tertiary text-xs">
                    Severities reported
                  </dt>
                  <dd>
                    {coverage.severities
                      ? coverage.severities.join(", ")
                      : "All"}
                    {coverage.fixed_only
                      ? "; only vulnerabilities with a fix"
                      : ""}
                  </dd>
                </div>
                <div>
                  <dt className="text-text-neutral-tertiary text-xs">
                    Complete
                  </dt>
                  <dd>
                    {coverage.complete
                      ? "Yes"
                      : "No; findings missing from this scan were not marked fixed."}
                  </dd>
                </div>
              </dl>
              {(coverage.reasons ?? []).length > 0 ? (
                <ul className="text-text-neutral-secondary list-disc pl-5 text-xs">
                  {(coverage.reasons ?? []).map((reason) => (
                    <li key={reason}>{reason}</li>
                  ))}
                </ul>
              ) : null}
            </SectionCard>
          ) : null}
        </div>

        {exportFormats.length > 0 ? (
          <SectionCard
            title="Exports"
            description="Converted from the stored scan report. Secret values are masked in every format."
          >
            <div className="flex flex-wrap gap-2">
              {exportFormats.map((format) => (
                <Button key={format} asChild size="sm" variant="outline">
                  <a
                    href={appSecDownloadHref(
                      APPSEC_DOWNLOAD_KIND.SCAN,
                      format,
                      {
                        id: runId,
                      },
                    )}
                  >
                    <Download aria-hidden="true" />
                    {EXPORT_LABEL[format] ?? format}
                  </a>
                </Button>
              ))}
            </div>
          </SectionCard>
        ) : null}

        <SectionCard
          title="Execution"
          description="How the scan ran, for diagnosis. Credentials are never recorded."
        >
          <dl className="grid grid-cols-1 gap-3 text-sm md:grid-cols-3">
            {Object.entries(options)
              .filter(([name]) => name !== "scanners")
              .map(([name, value]) => (
                <div key={name}>
                  <dt className="text-text-neutral-tertiary text-xs">
                    {capabilities?.options[name]?.label ??
                      name.replace(/_/g, " ")}
                  </dt>
                  <dd className="break-words">{optionValue(value)}</dd>
                </div>
              ))}
            {database.UpdatedAt ? (
              <div>
                <dt className="text-text-neutral-tertiary text-xs">
                  Vulnerability data published
                </dt>
                <dd>{formatAppSecDate(String(database.UpdatedAt))}</dd>
              </div>
            ) : null}
            {attributes.attempts && attributes.attempts > 1 ? (
              <div>
                <dt className="text-text-neutral-tertiary text-xs">Attempts</dt>
                <dd>{attributes.attempts}</dd>
              </div>
            ) : null}
          </dl>
          {warnings.length > 0 ? (
            <ul className="text-text-neutral-secondary list-disc pl-5 text-xs">
              {warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          ) : null}
          {attributes.command && attributes.command.length > 0 ? (
            <details>
              <summary className="text-text-neutral-secondary cursor-pointer text-sm">
                Command
              </summary>
              <pre className="bg-bg-neutral-tertiary mt-2 overflow-x-auto rounded-lg p-3 text-xs whitespace-pre-wrap">
                {attributes.command.join(" ")}
              </pre>
            </details>
          ) : null}
          {attributes.stderr_tail ? (
            <details open={Boolean(attributes.error)}>
              <summary className="text-text-neutral-secondary cursor-pointer text-sm">
                Scanner log (last lines)
              </summary>
              <pre className="bg-bg-neutral-tertiary mt-2 max-h-80 overflow-auto rounded-lg p-3 text-xs whitespace-pre-wrap">
                {attributes.stderr_tail}
              </pre>
            </details>
          ) : null}
        </SectionCard>
      </div>
    </ContentLayout>
  );
}
