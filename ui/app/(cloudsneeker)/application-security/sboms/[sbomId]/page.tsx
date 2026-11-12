import { Download, FileStack } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import {
  compareAppSecSboms,
  getAppSecSbom,
  listAppSecSbomComponents,
} from "@/cloudsneeker/actions/appsec";
import {
  AppSecComponentsTable,
  ComponentFiltersBar,
  componentsHref,
  componentsQuery,
  parseComponentFilters,
} from "@/cloudsneeker/components/appsec-components-table";
import {
  CountBars,
  Pager,
  TABLE_CLASS,
  TABLE_WRAPPER_CLASS,
  TD_CLASS,
  TD_PRIMARY_CLASS,
  TH_CLASS,
} from "@/cloudsneeker/components/appsec-ui";
import { pagesOf } from "@/cloudsneeker/components/area-triage-view";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  APPSEC_DOWNLOAD_KIND,
  APPSEC_SEGMENT,
  appSecDownloadHref,
  appSecSbomHref,
  attributesOf,
  formatAppSecDate,
} from "@/cloudsneeker/lib/appsec";
import {
  isListResponse,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
import { FORM_SELECT_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import type {
  AppSecComponentAttributes,
  AppSecDiffRow,
  AppSecResource,
  AppSecSbomAttributes,
  AppSecSbomComparison,
} from "@/cloudsneeker/types/appsec";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { cn } from "@/lib/utils";
import type { SearchParamsProps } from "@/types";

interface PageProps {
  params: Promise<{ sbomId: string }>;
  searchParams: Promise<SearchParamsProps>;
}

const FORMAT_LABEL: Record<string, string> = {
  cyclonedx: "CycloneDX",
  "spdx-json": "SPDX",
};

const one = (value: string | string[] | undefined): string =>
  ((Array.isArray(value) ? value[0] : value) ?? "").trim();

const DiffTable = ({
  title,
  rows,
  total,
}: {
  title: string;
  rows: AppSecDiffRow[];
  total: number;
}) =>
  total > 0 ? (
    <div className="flex flex-col gap-2">
      <h3 className="text-text-neutral-primary text-sm font-semibold">
        {title} ({total})
      </h3>
      <div className={TABLE_WRAPPER_CLASS}>
        <table className={cn(TABLE_CLASS, "min-w-[560px]")}>
          <thead>
            <tr>
              {["Component", "Ecosystem", "Version", "Licenses"].map(
                (heading) => (
                  <th key={heading} scope="col" className={TH_CLASS}>
                    {heading}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={`${row.ecosystem}:${row.name}:${row.location}`}>
                <td className={cn(TD_PRIMARY_CLASS, "max-w-xs")}>
                  <span className="break-all">{row.name}</span>
                  <p className="text-text-neutral-tertiary truncate text-xs">
                    {row.location}
                  </p>
                </td>
                <td className={TD_CLASS}>{row.ecosystem}</td>
                <td className={cn(TD_CLASS, "break-all")}>
                  {row.from_versions
                    ? `${row.from_versions.join(", ")} → ${(row.to_versions ?? []).join(", ")}`
                    : (row.versions ?? []).join(", ")}
                </td>
                <td className={cn(TD_CLASS, "text-xs")}>
                  {row.licenses.join(", ") || "Not stated"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  ) : null;

export default async function AppSecuritySbomPage({
  params,
  searchParams,
}: PageProps) {
  const { sbomId } = await params;
  const query = await searchParams;
  const filters = parseComponentFilters(query);
  const baseId = one(query.base);
  const sbom = attributesOf<AppSecSbomAttributes>(await getAppSecSbom(sbomId));
  if (!sbom) notFound();

  const pageBase = appSecSbomHref(sbomId);
  const extra: Record<string, string> = baseId ? { base: baseId } : {};
  const [componentsResponse, comparisonResponse] = await Promise.all([
    listAppSecSbomComponents(sbomId, componentsQuery(filters)),
    baseId ? compareAppSecSboms(sbomId, baseId) : Promise.resolve(null),
  ]);
  const components = isListResponse(componentsResponse)
    ? responseList<AppSecResource<AppSecComponentAttributes>>(
        componentsResponse,
      )
    : [];
  const comparison = attributesOf<AppSecSbomComparison>(comparisonResponse);
  const earlier = (sbom.versions ?? []).filter(
    (version) => version.version < sbom.version,
  );

  return (
    <ContentLayout
      title={`${sbom.target_name} · SBOM v${sbom.version}`}
      icon={<FileStack />}
    >
      <PageHeader
        meta={[
          { label: "Asset type", value: labelForTrivyMode(sbom.target_type) },
          { label: "Artifact", value: sbom.artifact_name || sbom.target_name },
          {
            label: "Source",
            value:
              sbom.source === "imported"
                ? `Imported document${sbom.document_format ? ` (${sbom.document_format})` : ""}`
                : "Generated from a scan",
          },
          { label: "Created", value: formatAppSecDate(sbom.inserted_at) },
          { label: "Components", value: sbom.component_count },
          {
            label: "Vulnerable components",
            value: sbom.vulnerable_component_count,
          },
        ]}
        actions={
          <>
            <Button asChild variant="ghost" size="sm">
              <Link href={appSecurityHref(APPSEC_SEGMENT.SBOMS)}>
                All SBOMs
              </Link>
            </Button>
            {(sbom.download_formats ?? ["cyclonedx"]).map((format) => (
              <Button key={format} asChild size="sm" variant="outline">
                <a
                  href={appSecDownloadHref(APPSEC_DOWNLOAD_KIND.SBOM, format, {
                    id: sbomId,
                  })}
                >
                  <Download aria-hidden="true" />
                  {FORMAT_LABEL[format] ?? format}
                </a>
              </Button>
            ))}
          </>
        }
      />
      <div className="flex flex-col gap-6">
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
          <SectionCard title="Ecosystems">
            <CountBars
              items={Object.entries(sbom.summary.ecosystems ?? {})
                .slice(0, 8)
                .map(([ecosystem, count]) => ({
                  key: ecosystem,
                  label: ecosystem || "unknown",
                  count,
                  href: componentsHref(pageBase, { ecosystem }, extra),
                }))}
            />
          </SectionCard>
          <SectionCard
            title="License distribution"
            description={`${sbom.summary.without_license ?? 0} component(s) state no license.`}
          >
            <CountBars
              items={Object.entries(sbom.summary.licenses ?? {})
                .slice(0, 8)
                .map(([license, count]) => ({
                  key: license,
                  label: license,
                  count,
                  href: componentsHref(pageBase, { license }, extra),
                }))}
            />
          </SectionCard>
        </div>

        <SectionCard
          title="Compare with an earlier version"
          description="Shows components added, removed and changed since the selected version of this asset."
        >
          {earlier.length === 0 ? (
            <p className="text-text-neutral-secondary text-sm">
              This is the first stored inventory of the asset. A later scan adds
              a version to compare with.
            </p>
          ) : (
            <form method="get" className="flex flex-wrap items-end gap-2">
              <label className="flex flex-col gap-1 text-xs">
                <span className="text-text-neutral-secondary font-semibold">
                  Earlier version
                </span>
                <select
                  name="base"
                  defaultValue={baseId}
                  className={cn(FORM_SELECT_CLASS, "w-72")}
                >
                  <option value="">Select a version</option>
                  {earlier.map((version) => (
                    <option key={version.id} value={version.id}>
                      v{version.version} ·{" "}
                      {formatAppSecDate(version.inserted_at)} ·{" "}
                      {version.component_count} components
                    </option>
                  ))}
                </select>
              </label>
              <Button type="submit" size="sm">
                Compare
              </Button>
            </form>
          )}
          {baseId && !comparison ? (
            <p role="alert" className="text-text-error-primary text-sm">
              The comparison could not be loaded.
            </p>
          ) : null}
          {comparison ? (
            <>
              <p className="text-text-neutral-primary text-sm">
                v{comparison.base.version} to v{comparison.head.version}:{" "}
                {comparison.counts.added} added, {comparison.counts.removed}{" "}
                removed, {comparison.counts.changed} changed,{" "}
                {comparison.counts.unchanged} unchanged.
                {comparison.truncated ? " Long lists are cut to 500 rows." : ""}
              </p>
              <DiffTable
                title="Added"
                rows={comparison.added}
                total={comparison.counts.added}
              />
              <DiffTable
                title="Version changed"
                rows={comparison.changed}
                total={comparison.counts.changed}
              />
              <DiffTable
                title="Removed"
                rows={comparison.removed}
                total={comparison.counts.removed}
              />
            </>
          ) : null}
        </SectionCard>

        <SectionCard title="Components">
          <ComponentFiltersBar
            ecosystems={Object.keys(sbom.summary.ecosystems ?? {})}
            licenses={Object.keys(sbom.summary.licenses ?? {})}
            sort={filters.sort}
          />
          {components.length === 0 ? (
            <EmptyState title="No components match" />
          ) : (
            <AppSecComponentsTable components={components} />
          )}
          <Pager
            page={filters.page}
            pages={pagesOf(componentsResponse)}
            hrefFor={(page) =>
              componentsHref(pageBase, { ...filters, page }, extra)
            }
          />
        </SectionCard>
      </div>
    </ContentLayout>
  );
}
