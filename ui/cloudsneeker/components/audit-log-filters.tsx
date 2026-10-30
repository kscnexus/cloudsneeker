import { Download } from "lucide-react";
import Link from "next/link";

import {
  AUDIT_CATEGORY_OPTIONS,
  type AuditLogFilters as AuditLogFilterValues,
  auditExportHref,
} from "@/cloudsneeker/lib/audit-log";
import { FORM_SELECT_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import { AUDIT_OUTCOME } from "@/cloudsneeker/types/audit";
import { Button } from "@/components/shadcn";

const FIELD_CLASS =
  "text-text-neutral-secondary flex min-w-0 flex-col gap-1 text-xs font-medium";

interface AuditLogFiltersProps {
  filters: AuditLogFilterValues;
}

/** Plain GET form: filters live in the URL, so no client state is needed. */
export const AuditLogFilters = ({ filters }: AuditLogFiltersProps) => (
  <form
    method="get"
    action={PRODUCT_ROUTE.AUDIT_LOG}
    aria-label="Audit log filters"
    className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-6 lg:items-end"
  >
    <div className={FIELD_CLASS}>
      <label htmlFor="audit-filter-action">Action</label>
      <select
        id="audit-filter-action"
        name="category"
        defaultValue={filters.category ?? ""}
        className={FORM_SELECT_CLASS}
      >
        <option value="">All actions</option>
        {AUDIT_CATEGORY_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
    <div className={FIELD_CLASS}>
      <label htmlFor="audit-filter-actor-email">Actor email</label>
      <input
        id="audit-filter-actor-email"
        type="search"
        name="actor"
        defaultValue={filters.actor ?? ""}
        placeholder="name@company.com"
        maxLength={254}
        className={FORM_SELECT_CLASS}
      />
    </div>
    <div className={FIELD_CLASS}>
      <label htmlFor="audit-filter-from">From</label>
      <input
        id="audit-filter-from"
        type="date"
        name="from"
        defaultValue={filters.from ?? ""}
        className={FORM_SELECT_CLASS}
      />
    </div>
    <div className={FIELD_CLASS}>
      <label htmlFor="audit-filter-to">To</label>
      <input
        id="audit-filter-to"
        type="date"
        name="to"
        defaultValue={filters.to ?? ""}
        className={FORM_SELECT_CLASS}
      />
    </div>
    <div className={FIELD_CLASS}>
      <label htmlFor="audit-filter-outcome">Outcome</label>
      <select
        id="audit-filter-outcome"
        name="outcome"
        defaultValue={filters.outcome ?? ""}
        className={FORM_SELECT_CLASS}
      >
        <option value="">Any outcome</option>
        <option value={AUDIT_OUTCOME.SUCCESS}>Success</option>
        <option value={AUDIT_OUTCOME.FAILURE}>Failure</option>
      </select>
    </div>
    <div className="flex flex-wrap items-center gap-2">
      <Button type="submit" size="sm">
        Apply
      </Button>
      <Button asChild variant="ghost" size="sm">
        <Link href={PRODUCT_ROUTE.AUDIT_LOG}>Reset</Link>
      </Button>
      <Button asChild variant="outline" size="sm">
        <a href={auditExportHref(filters)} download>
          <Download aria-hidden="true" />
          Export CSV
        </a>
      </Button>
    </div>
  </form>
);
