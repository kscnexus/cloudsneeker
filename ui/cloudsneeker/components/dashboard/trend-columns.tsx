import type { TrendPoint } from "@/cloudsneeker/lib/dashboards";
import { formatReportDay } from "@/cloudsneeker/lib/report-view";

interface TrendColumnsProps {
  points: TrendPoint[];
  /** What one column counts, e.g. "findings reported". */
  noun: string;
  emptyMessage: string;
}

/** Daily columns on a fixed time axis; empty days stay as a baseline. */
export const TrendColumns = ({
  points,
  noun,
  emptyMessage,
}: TrendColumnsProps) => {
  const max = Math.max(0, ...points.map((point) => point.value));
  const total = points.reduce((sum, point) => sum + point.value, 0);
  if (points.length === 0 || total === 0) {
    return (
      <p className="text-text-neutral-tertiary py-2 text-sm">{emptyMessage}</p>
    );
  }
  const first = points[0];
  const last = points[points.length - 1];
  return (
    <figure className="flex flex-col gap-2">
      <div
        role="img"
        aria-label={`${total.toLocaleString("en-US")} ${noun} from ${formatReportDay(first?.day)} to ${formatReportDay(last?.day)}`}
        className="flex h-28 items-end gap-1"
      >
        {points.map((point) => (
          <span
            key={point.day}
            title={`${formatReportDay(point.day)}: ${point.value.toLocaleString("en-US")} ${noun}`}
            className={
              point.value > 0
                ? "bg-button-tertiary min-h-1 flex-1 rounded-t-sm"
                : "bg-bg-neutral-tertiary h-1 flex-1 rounded-t-sm"
            }
            style={
              point.value > 0
                ? { height: `${Math.max(4, (point.value / max) * 100)}%` }
                : undefined
            }
          />
        ))}
      </div>
      <figcaption className="text-text-neutral-tertiary flex justify-between text-xs">
        <span>{formatReportDay(first?.day)}</span>
        <span>{formatReportDay(last?.day)}</span>
      </figcaption>
    </figure>
  );
};
