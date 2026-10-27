"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { cancelCustodianRun } from "@/cloudsneeker/actions/custodian";
import { Button } from "@/components/shadcn";

interface CustodianCancelRunButtonProps {
  runId: string;
}

export const CustodianCancelRunButton = ({
  runId,
}: CustodianCancelRunButtonProps) => {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);

  const onClick = async () => {
    setCancelling(true);
    setError(null);
    const result = await cancelCustodianRun(runId);
    setCancelling(false);

    if (result && "error" in result && result.error) {
      setError(
        typeof result.error === "string"
          ? result.error
          : "Failed to cancel dry-run.",
      );
      return;
    }

    router.refresh();
  };

  return (
    <div className="flex flex-col gap-2">
      <Button
        type="button"
        variant="ghost"
        size="sm"
        onClick={onClick}
        disabled={cancelling}
      >
        {cancelling ? "Cancelling…" : "Cancel pending dry-run"}
      </Button>
      {error ? <p className="text-text-error text-sm">{error}</p> : null}
    </div>
  );
};
