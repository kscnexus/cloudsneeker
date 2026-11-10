import { Archive, History } from "lucide-react";
import Link from "next/link";

import { listTrivyRuns } from "@/cloudsneeker/actions/trivy";
import {
  ARCHIVED_SCANS_PAGE_SIZE,
  getScanHistoryPage,
  groupRunsByTarget,
  responsePages,
  SCAN_ARCHIVE_DAYS,
  SCAN_HISTORY_VIEW,
  scanHistoryHref,
  type ScanHistoryView,
  SCANS_PER_TARGET,
} from "@/cloudsneeker/lib/app-security-scan-history";
import {
  isListResponse,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import type { TrivyRunResource } from "@/cloudsneeker/types/trivy";
import { Button } from "@/components/shadcn";

import { AppSecurityRunGroups } from "./app-security-run-groups";
import { AppSecurityRunList } from "./app-security-run-list";
import { SectionCard } from "./section-card";

/** The API pages at 100; 30 pages hold 20 scans each for 150 targets. */
const CURRENT_PAGE_SIZE = 100;
const MAX_CURRENT_PAGES = 30;

const LOAD_ERROR = "Scans could not be loaded. Reload the page in a moment.";

/** Each target's latest current (not archived) scans, every page. */
const loadCurrentRuns = async (): Promise<{
  runs: TrivyRunResource[];
  truncated: boolean;
} | null> => {
  const runs: TrivyRunResource[] = [];
  for (let page = 1; page <= MAX_CURRENT_PAGES; page += 1) {
    const response = await listTrivyRuns({
      "filter[latest_per_target]": String(SCANS_PER_TARGET),
      "filter[archived]": "false",
      "page[size]": String(CURRENT_PAGE_SIZE),
      "page[number]": String(page),
      sort: "-inserted_at",
    });
    if (!isListResponse(response))
      return page === 1 ? null : { runs, truncated: true };
    runs.push(...responseList<TrivyRunResource>(response));
    if (page >= responsePages(response)) return { runs, truncated: false };
  }
  return { runs, truncated: true };
};

const ErrorMessage = () => (
  <p className="text-text-error-primary text-sm">{LOAD_ERROR}</p>
);

const CurrentScans = async () => {
  const loaded = await loadCurrentRuns();
  return (
    <SectionCard
      title="Scans by target"
      description={`The latest ${SCANS_PER_TARGET} scans of each target, most recently scanned first. Scans older than one year move to the archive.`}
      actions={
        <Button asChild variant="ghost" size="sm">
          <Link href={scanHistoryHref(SCAN_HISTORY_VIEW.ARCHIVED)}>
            <Archive aria-hidden="true" />
            Archived scans
          </Link>
        </Button>
      }
    >
      {loaded ? (
        <div className="flex flex-col gap-3">
          <AppSecurityRunGroups
            groups={groupRunsByTarget(loaded.runs)}
            emptyMessage="No scans yet. Open a target and start a scan."
          />
          {loaded.truncated ? (
            <p className="text-text-neutral-tertiary text-xs">
              Showing the most recently scanned targets only. Open a target for
              its full history.
            </p>
          ) : null}
        </div>
      ) : (
        <ErrorMessage />
      )}
    </SectionCard>
  );
};

const ArchivedScans = async ({ page }: { page: number }) => {
  const response = await listTrivyRuns({
    "filter[archived]": "true",
    "page[size]": String(ARCHIVED_SCANS_PAGE_SIZE),
    "page[number]": String(page),
    sort: "-inserted_at",
  });
  const loaded = isListResponse(response);
  const pages = responsePages(response);
  const total = responseCount(response);

  return (
    <SectionCard
      title="Archived scans"
      description={`Scans older than ${SCAN_ARCHIVE_DAYS} days, newest first. Their findings are kept.${total !== null ? ` ${total} archived.` : ""}`}
      actions={
        <Button asChild variant="ghost" size="sm">
          <Link href={scanHistoryHref(SCAN_HISTORY_VIEW.CURRENT)}>
            <History aria-hidden="true" />
            Current scans
          </Link>
        </Button>
      }
    >
      {loaded ? (
        <div className="flex flex-col gap-3">
          <AppSecurityRunList
            runs={responseList<TrivyRunResource>(response)}
            emptyMessage="No archived scans. Scans move here after one year."
          />
          {pages > 1 ? (
            <nav
              aria-label="Archived scan pages"
              className="flex items-center justify-between gap-2"
            >
              {page > 1 ? (
                <Button asChild variant="outline" size="sm">
                  <Link
                    href={scanHistoryHref(SCAN_HISTORY_VIEW.ARCHIVED, page - 1)}
                  >
                    Newer
                  </Link>
                </Button>
              ) : (
                <span />
              )}
              <span className="text-text-neutral-secondary text-sm">
                {`Page ${page} of ${pages}`}
              </span>
              {page < pages ? (
                <Button asChild variant="outline" size="sm">
                  <Link
                    href={scanHistoryHref(SCAN_HISTORY_VIEW.ARCHIVED, page + 1)}
                  >
                    Older
                  </Link>
                </Button>
              ) : (
                <span />
              )}
            </nav>
          ) : null}
        </div>
      ) : (
        <ErrorMessage />
      )}
    </SectionCard>
  );
};

interface AppSecurityScanHistoryProps {
  view: ScanHistoryView;
  page?: string | string[];
}

/** Scans tab: current scans grouped by target, or the paged archive. */
export const AppSecurityScanHistory = ({
  view,
  page,
}: AppSecurityScanHistoryProps) =>
  view === SCAN_HISTORY_VIEW.ARCHIVED ? (
    <ArchivedScans page={getScanHistoryPage(page)} />
  ) : (
    <CurrentScans />
  );
