import { Badge } from "@/components/shadcn/badge/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/shadcn/table/table";
import { formatComplianceFrameworkTitle } from "@/lib/compliance/framework-title";
import { cn } from "@/lib/utils";

import {
  SCAN_COMPARISON_DELTA,
  type FrameworkComparisonRow,
  type FrameworkSnapshot,
  type ScanComparisonDelta,
} from "./scan-comparison";

interface ScanComparisonTableProps {
  rows: FrameworkComparisonRow[];
}

const DELTA_LABEL = {
  [SCAN_COMPARISON_DELTA.IMPROVED]: "Improved",
  [SCAN_COMPARISON_DELTA.REGRESSED]: "Regressed",
  [SCAN_COMPARISON_DELTA.UNCHANGED]: "Unchanged",
  [SCAN_COMPARISON_DELTA.ADDED]: "Added",
  [SCAN_COMPARISON_DELTA.REMOVED]: "Removed",
} as const;

const DELTA_BADGE_CLASS = {
  [SCAN_COMPARISON_DELTA.IMPROVED]: "text-text-success-primary",
  [SCAN_COMPARISON_DELTA.REGRESSED]: "text-text-error-primary",
  [SCAN_COMPARISON_DELTA.UNCHANGED]: "text-text-neutral-secondary",
  [SCAN_COMPARISON_DELTA.ADDED]: "text-text-neutral-primary",
  [SCAN_COMPARISON_DELTA.REMOVED]: "text-text-neutral-secondary",
} as const;

const formatScoreCell = (snapshot: FrameworkSnapshot | null): string => {
  if (!snapshot) return "—";
  return `${snapshot.score}% (${snapshot.passed}/${snapshot.total})`;
};

const formatDelta = (
  delta: ScanComparisonDelta,
  scoreDelta: number | null,
): string => {
  if (scoreDelta === null) return DELTA_LABEL[delta];
  if (scoreDelta === 0) return "0 pp";
  const sign = scoreDelta > 0 ? "+" : "";
  return `${sign}${scoreDelta} pp`;
};

export const ScanComparisonTable = ({ rows }: ScanComparisonTableProps) => {
  if (rows.length === 0) {
    return (
      <p className="text-text-neutral-secondary text-sm">
        No compliance frameworks to compare for these scans.
      </p>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Framework</TableHead>
          <TableHead>Baseline</TableHead>
          <TableHead>Compare</TableHead>
          <TableHead>Change</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((row) => (
          <TableRow key={row.key}>
            <TableCell className="font-medium">
              {formatComplianceFrameworkTitle(row.framework, row.version)}
            </TableCell>
            <TableCell>{formatScoreCell(row.baseline)}</TableCell>
            <TableCell>{formatScoreCell(row.compare)}</TableCell>
            <TableCell>
              <div className="flex flex-wrap items-center gap-2">
                <span className={cn("text-sm font-medium", DELTA_BADGE_CLASS[row.delta])}>
                  {formatDelta(row.delta, row.scoreDelta)}
                </span>
                <Badge variant="tag">{DELTA_LABEL[row.delta]}</Badge>
              </div>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
};
