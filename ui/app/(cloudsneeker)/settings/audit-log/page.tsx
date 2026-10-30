import { ScrollText, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { auth } from "@/auth.config";
import { listAuditEvents } from "@/cloudsneeker/actions/audit-log";
import { AuditLogFilters } from "@/cloudsneeker/components/audit-log-filters";
import { AuditLogTable } from "@/cloudsneeker/components/audit-log-table";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { StatTile, STAT_TILE_TONE } from "@/cloudsneeker/components/stat-tile";
import {
  AUDIT_PAGE_SIZE,
  type AuditLogFilters as AuditLogFilterValues,
  auditListParams,
  auditPageHref,
  parseAuditLogFilters,
} from "@/cloudsneeker/lib/audit-log";
import {
  isListResponse,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import type { AuditEventResource } from "@/cloudsneeker/types/audit";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import type { SearchParamsProps } from "@/types";

interface AuditLogPageProps {
  searchParams: Promise<SearchParamsProps>;
}

export default async function AuditLogPage({ searchParams }: AuditLogPageProps) {
  const filters = parseAuditLogFilters(await searchParams);

  return (
    <ContentLayout title="Audit log" icon={<ScrollText />}>
      <PageHeader description="Who did what in this organization: sign-ins, changes to users, roles, providers, credentials, integrations, mute rules, scans, and report sharing. Values such as passwords and keys are never recorded." />
      <Suspense fallback={<Skeleton className="h-64 w-full rounded-xl" />}>
        <SSRAuditLog filters={filters} />
      </Suspense>
    </ContentLayout>
  );
}

const errorMessage = (response: unknown): string => {
  const status = (response as { status?: unknown } | undefined)?.status;
  if (status === 403) {
    return "Viewing the audit log needs the manage account permission.";
  }
  const error = (response as { error?: unknown } | undefined)?.error;
  return typeof error === "string" && error
    ? error
    : "The audit log could not be loaded. Try again in a moment.";
};

const SSRAuditLog = async ({ filters }: { filters: AuditLogFilterValues }) => {
  const session = await auth();
  if (!session?.user?.permissions?.manage_account) {
    return (
      <EmptyState
        icon={<ShieldAlert />}
        title="Administrators only"
        description="Viewing the audit log needs the manage account permission. Ask an administrator for access."
      />
    );
  }

  const response = await listAuditEvents(auditListParams(filters));

  if (!isListResponse(response)) {
    return (
      <EmptyState
        icon={<ShieldAlert />}
        title="Audit log unavailable"
        description={errorMessage(response)}
        action={
          <Button asChild size="sm" variant="outline">
            <Link href={auditPageHref(filters, filters.page)}>Retry</Link>
          </Button>
        }
      />
    );
  }

  const events = responseList<AuditEventResource>(response);
  const count = responseCount(response) ?? events.length;
  const pages = Math.max(1, Math.ceil(count / AUDIT_PAGE_SIZE));
  const failures = events.filter(
    (event) => event.attributes.outcome === "failure",
  ).length;

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <StatTile label="Matching events" value={count} tone={STAT_TILE_TONE.ACCENT} />
        <StatTile
          label="Failures on this page"
          value={failures}
          tone={failures > 0 ? STAT_TILE_TONE.DANGER : STAT_TILE_TONE.SUCCESS}
        />
      </div>
      <SectionCard
        title="Events"
        description="Newest first. Filter by action, actor, date, or outcome, and export the result as CSV."
      >
        <AuditLogFilters filters={filters} />
        {events.length === 0 ? (
          <EmptyState
            icon={<ScrollText />}
            title="No events match"
            description="Change the filters, or come back after users sign in and make changes."
          />
        ) : (
          <AuditLogTable events={events} />
        )}
        {pages > 1 ? (
          <nav
            aria-label="Audit log pages"
            className="flex items-center justify-between gap-2 text-sm"
          >
            <span className="text-text-neutral-secondary">
              Page {filters.page} of {pages}
            </span>
            <div className="flex gap-2">
              {filters.page > 1 ? (
                <Button asChild size="sm" variant="outline">
                  <Link href={auditPageHref(filters, filters.page - 1)}>
                    Previous
                  </Link>
                </Button>
              ) : null}
              {filters.page < pages ? (
                <Button asChild size="sm" variant="outline">
                  <Link href={auditPageHref(filters, filters.page + 1)}>
                    Next
                  </Link>
                </Button>
              ) : null}
            </div>
          </nav>
        ) : null}
      </SectionCard>
    </div>
  );
};
