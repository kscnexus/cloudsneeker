"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { dryRunCustodianPolicy } from "@/cloudsneeker/actions/custodian";
import { Button } from "@/components/shadcn";

interface CustodianDryRunButtonProps {
  policyId: string;
}

export const CustodianDryRunButton = ({
  policyId,
}: CustodianDryRunButtonProps) => {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  const onClick = async () => {
    setRunning(true);
    setError(null);
    const result = await dryRunCustodianPolicy(policyId);
    setRunning(false);

    if (result && "error" in result && result.error) {
      setError(
        typeof result.error === "string"
          ? result.error
          : "Failed to enqueue dry-run.",
      );
      return;
    }

    router.refresh();
  };

  return (
    <div className="flex flex-col gap-2">
      <Button type="button" onClick={onClick} disabled={running}>
        {running ? "Starting dry-run…" : "Run dry-run"}
      </Button>
      {error ? <p className="text-text-error text-sm">{error}</p> : null}
    </div>
  );
};
