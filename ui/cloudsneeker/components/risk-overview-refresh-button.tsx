"use client";

import { RefreshCw } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { createReportRun } from "@/cloudsneeker/actions/reports";
import { REPORT_FORMAT, REPORT_TYPE_ID } from "@/cloudsneeker/types/reports";
import { Button } from "@/components/shadcn";

interface RiskOverviewRefreshButtonProps {
  label: string;
}

/** Starts a new executive report run, which rebuilds the risk view. */
export const RiskOverviewRefreshButton = ({
  label,
}: RiskOverviewRefreshButtonProps) => {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
