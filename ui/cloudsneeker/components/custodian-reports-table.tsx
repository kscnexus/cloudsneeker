import Link from "next/link";

import {
  formatDuration,
  type CustodianReportRow,
} from "@/cloudsneeker/lib/custodian-dashboard";
import { Badge } from "@/components/shadcn/badge/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/shadcn/table/table";

interface CustodianReportsTableProps {
  rows: CustodianReportRow[];
}

export const CustodianReportsTable = ({ rows }: CustodianReportsTableProps) => {
  if (rows.length === 0) {
    return (
      <p className="text-text-neutral-secondary text-sm">
        No Custodian dry-run reports yet. Completed and failed runs appear here.
      </p>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Policy</TableHead>
          <TableHead>Provider</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Trigger</TableHead>
          <TableHead>Resources</TableHead>
          <TableHead>Duration</TableHead>
          <TableHead>When</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((row) => (
          <TableRow key={row.runId}>
            <TableCell className="font-medium">
              <Link
                href={`/custodian/${row.policyId}/runs/${row.runId}`}
                className="hover:underline"
              >
                {row.policyName}
              </Link>
              {row.error ? (
                <p className="text-text-error mt-1 max-w-xs truncate text-xs">
                  {row.error}
                </p>
              ) : null}
            </TableCell>
            <TableCell>{row.providerLabel}</TableCell>
            <TableCell>
              <Badge variant="tag" className="capitalize">
                {row.status}
              </Badge>
            </TableCell>
            <TableCell className="capitalize">{row.trigger}</TableCell>
            <TableCell>
              {row.resourcesMatched === null ? (
                "—"
              ) : (
                <Link
                  href={`/custodian/${row.policyId}/runs/${row.runId}`}
                  className="hover:underline"
                >
                  {row.resourcesMatched}
                </Link>
              )}
            </TableCell>
            <TableCell>{formatDuration(row.durationMs)}</TableCell>
            <TableCell>
              {row.insertedAt
                ? new Date(row.insertedAt).toLocaleString()
                : "—"}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
};
