import Link from "next/link";

import {
  APPSEC_SEGMENT,
  APPSEC_SEVERITIES,
  APPSEC_WORKSPACES,
  appSecFindingsHref,
  appSecSeverityLabel,
  formatAppSecDate,
  sumCounts,
} from "@/cloudsneeker/lib/appsec";
import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import type {
  AppSecOverview,
  AppSecTrendPoint,
} from "@/cloudsneeker/types/appsec";
import { Button } from "@/components/shadcn";
import { cn } from "@/lib/utils";

import {
  CountBars,
  ROW_LINK_CLASS,
  SEVERITY_BAR_CLASS,
  TABLE_CLASS,
  TABLE_WRAPPER_CLASS,
  TD_CLASS,
  TD_PRIMARY_CLASS,
  TH_CLASS,
} from "./appsec-ui";
import { EmptyState } from "./empty-state";
import { runStatusLabel } from "./run-status-badge";
import { SectionCard } from "./section-card";
import { StatTile } from "./stat-tile";

const percent = (part: number, whole: number): string =>
  whole > 0 ? `${Math.round((part / whole) * 100)}%` : "–";

const CHART_HEIGHT = 120;

/** Detected and fixed findings per day, as paired bars. */
const TrendChart = ({ trend }: { trend: AppSecTrendPoint[] }) => {
  const max = Math.max(
    1,
    ...trend.map((point) => Math.max(point.detected, point.fixed)),
  );
  const step = 100 / trend.length;
  const totalDetected = trend.reduce((sum, point) => sum + point.detected, 0);
  const totalFixed = trend.reduce((sum, point) => sum + point.fixed, 0);
  return (
    <figure className="flex flex-col gap-2">
      <svg
        role="img"
        aria-label={`Findings detected and fixed per day: ${totalDetected} detected, ${totalFixed} fixed in the period.`}
        viewBox={`0 0 100 ${CHART_HEIGHT}`}
        preserveAspectRatio="none"
        className="h-32 w-full"
      >
        {trend.map((point, index) => {
          const x = index * step;
          const detected = (point.detected / max) * (CHART_HEIGHT - 4);
          const fixed = (point.fixed / max) * (CHART_HEIGHT - 4);
          return (
            <g key={point.date}>
              <title>{`${point.date}: ${point.detected} detected, ${point.fixed} fixed`}</title>
              <rect
                x={x + step * 0.1}
                y={CHART_HEIGHT - detected}
                width={step * 0.38}
                height={detected}
                className="fill-bg-data-high"
              />
              <rect
                x={x + step * 0.52}
                y={CHART_HEIGHT - fixed}
                width={step * 0.38}
                height={fixed}
                className="fill-bg-pass"
              />
            </g>
          );
        })}
      </svg>
      <figcaption className="text-text-neutral-tertiary flex flex-wrap items-center justify-between gap-2 text-xs">
        <span>
          {trend[0]?.date} to {trend[trend.length - 1]?.date}
        </span>
        <span className="flex items-center gap-4">
          <span className="flex items-center gap-1">
            <span className="bg-bg-data-high inline-block size-2 rounded-sm" />
            Detected ({totalDetected})
          </span>
          <span className="flex items-center gap-1">
            <span className="bg-bg-pass inline-block size-2 rounded-sm" />
            Fixed ({totalFixed})
          </span>
        </span>
      </figcaption>
    </figure>
  );
};

/** Application Security overview. Every figure comes from stored scan data. */
export const AppSecOverviewPanel = ({
  overview,
}: {
  overview: AppSecOverview;
}) => {
  const { inventory, scans, findings, components } = overview;
  const all = APPSEC_SEGMENT.FINDINGS;
  const scanTotal = scans.total;
  const failedScans = scans.by_status.failed ?? 0;

  if (inventory.targets === 0) {
    return (
      <SectionCard title="Get started">
        <EmptyState
          title="No assets yet"
          description="Add a repository, container image, archive, SBOM or cluster as a target and run a scan. Findings, components and trends appear here from the scan results."
          action={
            <Button asChild size="sm">
              <Link href={appSecurityHref("new")}>Add a target</Link>
            </Button>
          }
        />
      </SectionCard>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
        <StatTile
          label="Applications"
          value={inventory.applications}
          hint={
            inventory.unassigned_targets
              ? `${inventory.unassigned_targets} asset(s) unassigned`
              : "All assets assigned"
          }
          href={appSecurityHref(APPSEC_SEGMENT.APPLICATIONS)}
        />
        <StatTile
          label="Assets"
          value={inventory.targets}
          hint={`${inventory.scanned_targets} scanned`}
          href={appSecurityHref(APPSEC_SEGMENT.SCANS)}
        />
        <StatTile
          label="Scans"
          value={scanTotal}
          hint={
            scans.last
              ? `Last: ${runStatusLabel(scans.last.status)}, ${formatAppSecDate(scans.last.at)}`
              : "None yet"
          }
          tone={failedScans > 0 ? "warning" : "neutral"}
          href={appSecurityHref(APPSEC_SEGMENT.SCANS)}
        />
        <StatTile
          label="Active findings"
          value={findings.active}
          hint={`${findings.suppressed} suppressed`}
          href={appSecFindingsHref(all)}
        />
        <StatTile
          label="Critical"
          value={findings.by_severity.critical ?? 0}
          tone="critical"
          href={appSecFindingsHref(all, { severities: ["critical"] })}
        />
        <StatTile
          label="High"
          value={findings.by_severity.high ?? 0}
          tone="high"
          href={appSecFindingsHref(all, { severities: ["high"] })}
        />
        <StatTile
          label="Past deadline"
          value={findings.overdue}
          tone="warning"
          href={appSecFindingsHref(all, { overdue: true })}
        />
        <StatTile
          label={`Fixed, ${overview.window_days} d`}
          value={overview.fixed_in_window}
          tone="success"
          hint={
            overview.mean_days_to_fix !== null
              ? `Mean ${overview.mean_days_to_fix} d to fix`
              : "No fixes in the period"
          }
          href={appSecFindingsHref(all, { states: ["fixed"] })}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <SectionCard
          title="Findings by category"
          description="Active findings. Each category has its own workspace."
        >
          <CountBars
            items={APPSEC_WORKSPACES.filter(
              (workspace) => workspace.category !== null,
            ).map((workspace) => ({
              key: workspace.segment,
              label: workspace.title,
              count: findings.by_category[workspace.category ?? ""] ?? 0,
              href: appSecFindingsHref(workspace.segment),
            }))}
          />
        </SectionCard>
        <SectionCard
          title="Severity distribution"
          description="Scanner severity of active findings."
        >
          <CountBars
            items={APPSEC_SEVERITIES.map((severity) => ({
              key: severity,
              label: appSecSeverityLabel(severity),
              count: findings.by_severity[severity] ?? 0,
              href: appSecFindingsHref(all, { severities: [severity] }),
              className: SEVERITY_BAR_CLASS[severity],
            }))}
          />
        </SectionCard>
        <SectionCard
          title="Priority"
          description="Calculated from severity, exploitability, fix availability and application context."
        >
          <CountBars
            items={(["urgent", "high", "medium", "low"] as const).map(
              (priority) => ({
                key: priority,
                label: priority.charAt(0).toUpperCase() + priority.slice(1),
                count: findings.by_priority[priority] ?? 0,
                href: appSecFindingsHref(all, { priorities: [priority] }),
                className:
                  priority === "urgent"
                    ? "bg-bg-data-critical"
                    : priority === "high"
                      ? "bg-bg-data-high"
                      : priority === "medium"
                        ? "bg-bg-data-medium"
                        : "bg-bg-data-low",
              }),
            )}
          />
        </SectionCard>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <SectionCard
          title="Finding trend"
          description={`New findings and fixes per day, last ${overview.window_days} days.`}
          className="xl:col-span-2"
        >
          <TrendChart trend={overview.trend} />
        </SectionCard>
        <SectionCard
          title="Vulnerabilities"
          description="Separate counts; none of them is a total of the others."
          actions={
            <Button asChild size="xs" variant="outline">
              <Link href={appSecurityHref(APPSEC_SEGMENT.VULNERABILITIES)}>
                Open
              </Link>
            </Button>
          }
        >
          <dl className="grid grid-cols-2 gap-3 text-sm">
            {[
              ["Instances", findings.vulnerabilities.instances],
              ["Unique advisories", findings.vulnerabilities.unique_ids],
              ["Affected packages", findings.vulnerabilities.affected_packages],
              ["Fix available", findings.vulnerabilities.fixable],
              ["No fix yet", findings.vulnerabilities.unfixed],
            ].map(([label, value]) => (
              <div key={label} className="flex flex-col">
                <dt className="text-text-neutral-tertiary text-xs">{label}</dt>
                <dd className="text-text-neutral-primary text-lg font-semibold tabular-nums">
                  {value}
                </dd>
              </div>
            ))}
          </dl>
        </SectionCard>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard
          title="Assets needing attention"
          description="Ordered by urgent, then critical, then high findings."
        >
          {overview.top_targets.length === 0 ? (
            <EmptyState title="No active findings" />
          ) : (
            <div className={TABLE_WRAPPER_CLASS}>
              <table className={cn(TABLE_CLASS, "min-w-[480px]")}>
                <thead>
                  <tr>
                    <th scope="col" className={TH_CLASS}>
                      Asset
                    </th>
                    <th scope="col" className={TH_CLASS}>
                      Urgent
                    </th>
                    <th scope="col" className={TH_CLASS}>
                      Critical
                    </th>
                    <th scope="col" className={TH_CLASS}>
                      High
                    </th>
                    <th scope="col" className={TH_CLASS}>
                      Active
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {overview.top_targets.map((target) => (
                    <tr key={target.target_id}>
                      <td className={TD_PRIMARY_CLASS}>
                        <Link
                          href={appSecFindingsHref(all, {
                            target: target.target_id,
                          })}
                          className={ROW_LINK_CLASS}
                        >
                          {target.name}
                        </Link>
                        <p className="text-text-neutral-tertiary text-xs">
                          {target.application ? `${target.application} · ` : ""}
                          {labelForTrivyMode(target.target_type)}
                        </p>
                      </td>
                      <td className={cn(TD_CLASS, "tabular-nums")}>
                        {target.urgent}
                      </td>
                      <td className={cn(TD_CLASS, "tabular-nums")}>
                        {target.critical}
                      </td>
                      <td className={cn(TD_CLASS, "tabular-nums")}>
                        {target.high}
                      </td>
                      <td className={cn(TD_CLASS, "tabular-nums")}>
                        {target.total}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </SectionCard>
        <SectionCard
          title="Most vulnerable packages"
          description="Packages with the most distinct advisories across assets."
        >
          {overview.top_packages.length === 0 ? (
            <EmptyState title="No vulnerable packages" />
          ) : (
            <div className={TABLE_WRAPPER_CLASS}>
              <table className={cn(TABLE_CLASS, "min-w-[480px]")}>
                <thead>
                  <tr>
                    <th scope="col" className={TH_CLASS}>
                      Package
                    </th>
                    <th scope="col" className={TH_CLASS}>
                      Advisories
                    </th>
                    <th scope="col" className={TH_CLASS}>
                      Critical
                    </th>
                    <th scope="col" className={TH_CLASS}>
                      High
                    </th>
                    <th scope="col" className={TH_CLASS}>
                      Assets
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {overview.top_packages.map((pkg) => (
                    <tr key={`${pkg.ecosystem}:${pkg.pkg_name}`}>
                      <td className={TD_PRIMARY_CLASS}>
                        <Link
                          href={appSecFindingsHref(
                            APPSEC_SEGMENT.VULNERABILITIES,
                            { pkg: pkg.pkg_name },
                          )}
                          className={ROW_LINK_CLASS}
                        >
                          {pkg.pkg_name}
                        </Link>
                        <p className="text-text-neutral-tertiary text-xs">
                          {pkg.ecosystem}
                        </p>
                      </td>
                      <td className={cn(TD_CLASS, "tabular-nums")}>
                        {pkg.vulnerabilities}
                      </td>
                      <td className={cn(TD_CLASS, "tabular-nums")}>
                        {pkg.critical}
                      </td>
                      <td className={cn(TD_CLASS, "tabular-nums")}>
                        {pkg.high}
                      </td>
                      <td className={cn(TD_CLASS, "tabular-nums")}>
                        {pkg.targets}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </SectionCard>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <SectionCard
          title="Software inventory"
          description="Components in the newest SBOM of each asset."
          actions={
            <Button asChild size="xs" variant="outline">
              <Link href={appSecurityHref(APPSEC_SEGMENT.COMPONENTS)}>
                Open
              </Link>
            </Button>
          }
        >
          <dl className="grid grid-cols-3 gap-3 text-sm">
            {[
              ["Components", components.total],
              ["Vulnerable", components.vulnerable],
              [
                "SBOM coverage",
                `${components.targets_with_sbom} of ${inventory.targets} (${percent(components.targets_with_sbom, inventory.targets)})`,
              ],
            ].map(([label, value]) => (
              <div key={label} className="flex flex-col">
                <dt className="text-text-neutral-tertiary text-xs">{label}</dt>
                <dd className="text-text-neutral-primary font-semibold tabular-nums">
                  {value}
                </dd>
              </div>
            ))}
          </dl>
          <CountBars
            items={Object.entries(components.by_ecosystem).map(
              ([ecosystem, count]) => ({
                key: ecosystem,
                label: ecosystem || "unknown",
                count,
              }),
            )}
          />
        </SectionCard>
        <SectionCard
          title="Scan execution"
          description={`${sumCounts(scans.by_status)} scans in total.`}
        >
          <CountBars
            items={Object.entries(scans.by_status).map(([status, count]) => ({
              key: status,
              label: runStatusLabel(status),
              count,
              className:
                status === "failed"
                  ? "bg-bg-fail"
                  : status === "completed"
                    ? "bg-bg-pass"
                    : undefined,
            }))}
          />
        </SectionCard>
        <SectionCard
          title="Assets by type"
          description={`${inventory.scanned_targets} of ${inventory.targets} have a completed scan.`}
        >
          <CountBars
            items={Object.entries(inventory.targets_by_type).map(
              ([mode, count]) => ({
                key: mode,
                label: labelForTrivyMode(mode),
                count,
              }),
            )}
          />
        </SectionCard>
      </div>
      <p className="text-text-neutral-tertiary text-xs">
        Calculated {formatAppSecDate(overview.generated_at)} UTC from stored
        scan results.
      </p>
    </div>
  );
};
