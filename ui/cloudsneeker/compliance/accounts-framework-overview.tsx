import Link from "next/link";

import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { loadComplianceFrameworks } from "@/cloudsneeker/lib/dashboard-data";
import {
  rankFrameworksByGap,
  summarizeCompliance,
} from "@/cloudsneeker/lib/dashboards";
import {
  TABLE_BODY_CLASS,
  TABLE_CLASS,
  TABLE_FRAME_CLASS,
  TABLE_HEAD_CLASS,
  TABLE_HEADER_CELL_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import { cn } from "@/lib/utils";

import {
  MULTI_SCAN_VIEW,
  multiScanViewHref,
  type ProviderTypeOption,
} from "./accounts-view";

interface AccountsFrameworkOverviewProps {
  options: ProviderTypeOption[];
  providerType: string | null;
}

const scoreTone = (score: number): string =>
  score >= 80 ? "bg-bg-pass" : score >= 50 ? "bg-bg-warning" : "bg-bg-fail";

/** Every framework across the latest scan of each account of one provider
 * type: requirement counts and pass rate per framework. */
export const AccountsFrameworkOverview = async ({
  options,
  providerType,
}: AccountsFrameworkOverviewProps) => {
  if (!providerType) {
    return (
      <EmptyState
        title="No cloud or SaaS scans yet"
        description="Frameworks appear once an account of a supported provider has a completed scan."
      />
    );
  }
  const rows = await loadComplianceFrameworks({
    "filter[provider_type]": providerType,
  });
  const selected = options.find((option) => option.value === providerType);
  const summary = rows ? summarizeCompliance(rows) : null;

  return (
    <div className="flex flex-col gap-4">
      <nav aria-label="Provider type" className="flex flex-wrap gap-2">
        {options.map((option) => (
          <Link
            key={option.value}
            href={multiScanViewHref(MULTI_SCAN_VIEW.ACCOUNTS, option.value)}
            aria-current={option.value === providerType ? "page" : undefined}
            className={cn(
              "rounded-full border px-3 py-1 text-sm",
              option.value === providerType
                ? "border-button-primary text-text-neutral-primary font-medium"
                : "border-border-neutral-secondary text-text-neutral-secondary",
            )}
          >
            {option.label} · {option.accounts}
          </Link>
        ))}
      </nav>
      <SectionCard
        title={`${selected?.label ?? providerType} frameworks across accounts`}
        description={`Latest scan of each of ${selected?.accounts ?? 0} account(s). Frameworks with the most failed requirements first.`}
      >
        {rows === null ? (
          <p role="alert" className="text-text-error-primary text-sm">
            Compliance results could not be loaded. Reload the page in a moment.
          </p>
        ) : rows.length === 0 ? (
          <EmptyState
            title="No compliance results yet"
            description="Results appear after a scan of this provider finishes building its compliance summary."
          />
        ) : (
          <>
            {summary && summary.percent !== null ? (
              <p className="text-text-neutral-secondary mb-3 text-sm">
                {summary.frameworkCount} frameworks · {summary.percent}% of{" "}
                {summary.total} requirements passed
              </p>
            ) : null}
            <div className={TABLE_FRAME_CLASS}>
              <table className={TABLE_CLASS}>
                <thead className={TABLE_HEAD_CLASS}>
                  <tr>
                    <th className={TABLE_HEADER_CELL_CLASS}>Framework</th>
                    <th className={TABLE_HEADER_CELL_CLASS}>Pass rate</th>
                    <th className={TABLE_HEADER_CELL_CLASS}>Passed</th>
                    <th className={TABLE_HEADER_CELL_CLASS}>Failed</th>
                    <th className={TABLE_HEADER_CELL_CLASS}>Manual</th>
                    <th className={TABLE_HEADER_CELL_CLASS}>Requirements</th>
                  </tr>
                </thead>
                <tbody className={TABLE_BODY_CLASS}>
                  {rankFrameworksByGap(rows).map((row) => (
                    <tr key={row.id}>
                      <td className="px-3 py-2 text-sm font-medium">
                        {row.label}
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <div className="bg-bg-neutral-tertiary h-2 w-24 overflow-hidden rounded-full">
                            <div
                              className={cn("h-full", scoreTone(row.score))}
                              style={{ width: `${Math.round(row.score)}%` }}
                            />
                          </div>
                          <span className="text-sm">
                            {Math.round(row.score)}%
                          </span>
                        </div>
                      </td>
                      <td className="px-3 py-2 text-sm">{row.passed}</td>
                      <td className="px-3 py-2 text-sm">{row.failed}</td>
                      <td className="px-3 py-2 text-sm">{row.manual}</td>
                      <td className="px-3 py-2 text-sm">{row.total}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </SectionCard>
    </div>
  );
};
