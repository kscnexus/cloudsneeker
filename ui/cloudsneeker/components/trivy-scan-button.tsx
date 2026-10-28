"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { scanTrivyTarget } from "@/cloudsneeker/actions/trivy";
import { Button } from "@/components/shadcn";

interface TrivyScanButtonProps {
  targetId: string;
}

export const TrivyScanButton = ({ targetId }: TrivyScanButtonProps) => {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onScan = async () => {
    setPending(true);
    setError(null);
    const result = await scanTrivyTarget(targetId);
    setPending(false);
    if (result && "error" in result && result.error) {
      setError(
        typeof result.error === "string"
          ? result.error
          : "Failed to enqueue Trivy scan.",
      );
      return;
    }
    router.refresh();
  };

  return (
    <div className="flex flex-col items-end gap-1">
      <Button type="button" size="sm" disabled={pending} onClick={onScan}>
        {pending ? "Starting…" : "Run scan"}
      </Button>
      {error ? (
        <span className="text-text-error-primary text-xs">{error}</span>
      ) : null}
    </div>
  );
};
