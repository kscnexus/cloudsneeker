import Link from "next/link";

import { listOperatorAuditEvents } from "@/cloudsneeker/actions/operator";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { OperatorAuditTable } from "@/cloudsneeker/components/operator-audit-table";
import { OperatorLoadError } from "@/cloudsneeker/components/operator-shell";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  isListResponse,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import { OPERATOR_PAGE_SIZE, responseError } from "@/cloudsneeker/lib/operator";
import { OPERATOR_ROUTE } from "@/cloudsneeker/routes";
import type { OperatorAuditResource } from "@/cloudsneeker/types/operator";
import { Button, Input, Label } from "@/components/shadcn";

interface AuditPageProps {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

const first = (value: string | string[] | undefined): string =>
  (Array.isArray(value) ? value[0] : value)?.trim() ?? "";

const pageHref = (action: string, tenant: string, page: number): string => {
  const query = new URLSearchParams();
  if (action) query.set("action", action);
  if (tenant) query.set("tenant", tenant);
  if (page > 1) query.set("page", String(page));
  const text = query.toString();
  return text ? `${OPERATOR_ROUTE.AUDIT}?${text}` : OPERATOR_ROUTE.AUDIT;
};

export default async function OperatorAuditPage({
  searchParams,
}: AuditPageProps) {
  const params = await searchParams;
  const action = first(params.action);
  const tenant = first(params.tenant);
  const parsedPage = Number.parseInt(first(params.page), 10);
  const page = Number.isFinite(parsedPage) && parsedPage > 0 ? parsedPage : 1;

  const response = await listOperatorAuditEvents({
    "filter[action]": action || undefined,
    "filter[tenant]": tenant || undefined,
    "page[number]": String(page),
    "page[size]": String(OPERATOR_PAGE_SIZE),
  });

  return (
    <>
      <PageHeader
        title="Operator audit"
        description="Every change made in the operator console or with the operator command: who, when, which customer, and which fields. Values are never recorded."
      />
      <SectionCard title="Events">
        <form
          method="get"
          action={OPERATOR_ROUTE.AUDIT}
          aria-label="Filter operator audit events"
          className="grid grid-cols-1 gap-3 sm:grid-cols-3 sm:items-end"
        >
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="audit-action">Action starts with</Label>
            <Input
              id="audit-action"
              name="action"
              defaultValue={action}
              placeholder="subscription."
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="audit-tenant">Tenant id</Label>
            <Input id="audit-tenant" name="tenant" defaultValue={tenant} />
          </div>
          <div className="flex gap-2">
            <Button asChild size="sm" variant="outline">
              <Link href={OPERATOR_ROUTE.AUDIT}>Clear</Link>
            </Button>
            <Button type="submit" size="sm">
              Apply
            </Button>
          </div>
        </form>
        <AuditResults
          response={response}
          action={action}
          tenant={tenant}
          page={page}
        />
      </SectionCard>
    </>
  );
}

const AuditResults = ({
  response,
  action,
  tenant,
  page,
}: {
  response: unknown;
  action: string;
  tenant: string;
  page: number;
}) => {
  if (!isListResponse(response)) {
    return (
      <OperatorLoadError
        title="Operator audit unavailable"
        message={responseError(
          response,
          "The operator audit log could not be loaded.",
        )}
        retryHref={pageHref(action, tenant, page)}
      />
    );
  }
  const events = responseList<OperatorAuditResource>(response);
  const count = responseCount(response) ?? events.length;
  const pages = Math.max(1, Math.ceil(count / OPERATOR_PAGE_SIZE));
  if (events.length === 0) {
    return (
      <EmptyState
        title="No events match"
        description="Operator changes appear here as soon as they are made."
      />
    );
  }
  return (
    <>
      <OperatorAuditTable events={events} />
      {pages > 1 ? (
        <nav
          aria-label="Audit pages"
          className="flex items-center justify-between gap-2 text-sm"
        >
          <span className="text-text-neutral-secondary">
            Page {page} of {pages}
          </span>
          <div className="flex gap-2">
            {page > 1 ? (
              <Button asChild size="sm" variant="outline">
                <Link href={pageHref(action, tenant, page - 1)}>Previous</Link>
              </Button>
            ) : null}
            {page < pages ? (
              <Button asChild size="sm" variant="outline">
                <Link href={pageHref(action, tenant, page + 1)}>Next</Link>
              </Button>
            ) : null}
          </div>
        </nav>
      ) : null}
    </>
  );
};
