"use client";

import { RefreshCw } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { createReportRun } from "@/cloudsneeker/actions/reports";
import { REPORT_FORMAT, REPORT_TYPE_ID } from "@/cloudsneeker/types/reports";
import { Button } from "@/components/shadcn";

interface RiskOverviewRefreshButtonProps {
  label: string;
  /** Start a run once on mount for this snapshot (it is out of date). The
   * key stops a failed run from being retried on every visit. */
  autoStartKey?: string;
}

const AUTO_START_STORAGE_PREFIX = "cs-risk-auto-refresh:";

/** True the first time this browser session sees `key`. */
const claimAutoStart = (key: string): boolean => {
  try {
    const storageKey = `${AUTO_START_STORAGE_PREFIX}${key}`;
    if (window.sessionStorage.getItem(storageKey)) return false;
    window.sessionStorage.setItem(storageKey, "1");
    return true;
  } catch {
    return false;
  }
};

/** Starts a new executive report run, which rebuilds the risk view. */
export const RiskOverviewRefreshButton = ({
  label,
  autoStartKey,
}: RiskOverviewRefreshButtonProps) => {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const autoStarted = useRef(false);

  const onClick = async () => {
    setPending(true);
    setError(null);
    const result: unknown = await createReportRun({
      reportType: REPORT_TYPE_ID.EXECUTIVE,
      params: {},
      formats: [REPORT_FORMAT.PDF],
    });
    setPending(false);
    const failure =
      result && typeof result === "object" && "error" in result
        ? (result as { error?: unknown }).error
        : null;
    if (failure) {
      setError(
        typeof failure === "string"
          ? failure
          : "Could not refresh the risk view.",
      );
      return;
    }
    router.refresh();
  };

  useEffect(() => {
    if (!autoStartKey || autoStarted.current) return;
    autoStarted.current = true;
    if (claimAutoStart(autoStartKey)) void onClick();
    // Runs once per snapshot; onClick is recreated on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoStartKey]);

  return (
    <div className="flex flex-col items-start gap-1">
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={onClick}
        disabled={pending}
      >
        <RefreshCw aria-hidden="true" />
        {pending ? "Starting…" : label}
      </Button>
      {error ? (
        <p role="alert" className="text-text-error-primary text-xs">
          {error}
        </p>
      ) : null}
    </div>
  );
};
