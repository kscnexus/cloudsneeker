"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { cancelAppSecScan } from "@/cloudsneeker/actions/appsec";
import { actionError } from "@/cloudsneeker/lib/appsec";
import { Button } from "@/components/shadcn";

/** Stops a queued or running scan. */
export const AppSecCancelScanButton = ({ runId }: { runId: string }) => {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);

  const onClick = async () => {
    setCancelling(true);
    setError(null);
    const result = await cancelAppSecScan(runId);
    setCancelling(false);
    const failure = actionError(result);
    if (failure) {
      setError(failure);
      return;
    }
    router.refresh();
  };

  return (
    <div className="flex flex-col items-end gap-1">
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={onClick}
        disabled={cancelling}
      >
        {cancelling ? "Cancelling…" : "Cancel scan"}
      </Button>
      {error ? (
        <p role="alert" className="text-text-error-primary text-xs">
          {error}
        </p>
      ) : null}
    </div>
  );
};
