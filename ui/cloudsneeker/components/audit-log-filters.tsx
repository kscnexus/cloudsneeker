import { Download } from "lucide-react";

import {
  AUDIT_CATEGORY_OPTIONS,
  AUDIT_PARAM,
  type AuditLogFilters as AuditLogFilterValues,
  auditExportHref,
} from "@/cloudsneeker/lib/audit-log";
import { AUDIT_OUTCOME } from "@/cloudsneeker/types/audit";
import { Button } from "@/components/shadcn";
import { DataTableSearch } from "@/components/shadcn/table/data-table-search";

import { StandardFilters } from "./standard/standard-filters";

interface AuditLogFiltersProps {
  filters: AuditLogFilterValues;
}

/** The Cloud Security Findings filter bar: action, outcome, a start date and
 * the actor search, applied together and kept in the URL. */
export const AuditLogFilters = ({ filters }: AuditLogFiltersProps) => (
  <div className="flex flex-col gap-3" aria-label="Audit log filters">
    <StandardFilters
      testIdPrefix="audit-log"
      filters={[
        {
          key: AUDIT_PARAM.CATEGORY,
          label: "Actions",
          single: true,
          options: AUDIT_CATEGORY_OPTIONS.map((option) => ({
            value: option.value,
            label: option.label,
          })),
        },
        {
          key: AUDIT_PARAM.OUTCOME,
          label: "Outcomes",
          single: true,
          options: [
            { value: AUDIT_OUTCOME.SUCCESS, label: "Success" },
            { value: AUDIT_OUTCOME.FAILURE, label: "Failure" },
          ],
        },
      ]}
      dateKey={AUDIT_PARAM.FROM}
      dateLabel="From"
      trailingControls={
        <>
          <div className="w-full md:w-72">
            <DataTableSearch placeholder="Actor email (press Enter)" />
          </div>
          <Button asChild variant="outline" size="lg">
            <a href={auditExportHref(filters)} download>
              <Download aria-hidden="true" />
              Export CSV
            </a>
          </Button>
        </>
      }
    />
  </div>
);
