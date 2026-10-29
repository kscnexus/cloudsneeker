import { Badge } from "@/components/shadcn/badge/badge";

const RUN_STATUS_VARIANT = {
  completed: "success",
  failed: "error",
  running: "info",
  pending: "warning",
} as const;

type RunStatusVariant =
  (typeof RUN_STATUS_VARIANT)[keyof typeof RUN_STATUS_VARIANT];

const RUN_STATUS_LABEL: Record<string, string> = {
  completed: "Completed",
  failed: "Failed",
  running: "Running",
  pending: "Queued",
};

export const runStatusVariant = (status: string): RunStatusVariant | "tag" =>
  RUN_STATUS_VARIANT[status as keyof typeof RUN_STATUS_VARIANT] ?? "tag";

export const runStatusLabel = (status: string): string =>
  RUN_STATUS_LABEL[status] ??
  (status ? status.charAt(0).toUpperCase() + status.slice(1) : "Unknown");

/** Status pill for application security scans and governance dry-runs. */
export const RunStatusBadge = ({ status }: { status: string }) => (
  <Badge variant={runStatusVariant(status)}>{runStatusLabel(status)}</Badge>
);
