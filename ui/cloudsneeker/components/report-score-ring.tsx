import { SCORE_TONE_COLOR, scoreTone } from "@/cloudsneeker/lib/report-view";

interface ReportScoreRingProps {
  score: number | null;
  grade: string;
  size?: number;
}

const STROKE = 10;

export const ReportScoreRing = ({
  score,
  grade,
  size = 148,
}: ReportScoreRingProps) => {
  const radius = (size - STROKE) / 2;
  const circumference = 2 * Math.PI * radius;
  const value = score === null ? 0 : Math.max(0, Math.min(100, score));
  const offset = circumference * (1 - value / 100);
  const color = SCORE_TONE_COLOR[scoreTone(score)];

  return (
    <div
      className="relative shrink-0"
      style={{ width: size, height: size }}
      role="img"
      aria-label={
        score === null
          ? "No security score"
          : `Security score ${Math.round(value)} of 100, grade ${grade}`
      }
    >
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--border-neutral-secondary)"
          strokeWidth={STROKE}
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={STROKE}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-text-neutral-primary text-4xl font-bold leading-none">
          {grade}
        </span>
        <span className="text-text-neutral-secondary mt-1 text-xs">
          {score === null ? "No data" : `${Math.round(value)} / 100`}
        </span>
      </div>
    </div>
  );
};
