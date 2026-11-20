"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { scanTrivyTarget } from "@/cloudsneeker/actions/trivy";
import { Button, Input } from "@/components/shadcn";

interface TargetBranchScanProps {
  targetId: string;
  /** The target's other branches (`config.branches`), names or patterns. */
  extraBranches: string[];
}

const errorOf = (result: unknown): string | null => {
  if (!result || typeof result !== "object" || !("error" in result)) {
    return null;
  }
  const value = (result as { error?: unknown }).error;
  if (!value) return null;
  return typeof value === "string" ? value : "Failed to start the scan.";
};

/**
 * Scan one branch of a repository target on demand, or every other branch
 * now (also the ones whose latest commit was already scanned).
 */
export const TargetBranchScan = ({
  targetId,
  extraBranches,
}: TargetBranchScanProps) => {
  const router = useRouter();
  const [branch, setBranch] = useState("");
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const start = async (options: { branch?: string; allBranches?: boolean }) => {
    setPending(true);
    setError(null);
    setMessage(null);
    const result = await scanTrivyTarget(targetId, options);
    setPending(false);
    const failure = errorOf(result);
    if (failure) {
      setError(failure);
      return;
    }
    setMessage(
      options.branch
        ? `Scan of ${options.branch} queued.`
        : "Main branch queued; the other branches are queued as they are listed.",
    );
    setBranch("");
    router.refresh();
  };

  return (
    <div className="flex flex-col gap-3">
      <form
        className="flex flex-col gap-2 sm:flex-row sm:items-center"
        onSubmit={(event) => {
          event.preventDefault();
          if (branch.trim()) void start({ branch: branch.trim() });
        }}
      >
        <label htmlFor="target-branch-scan" className="sr-only">
          Branch to scan
        </label>
        <Input
          id="target-branch-scan"
          className="sm:max-w-xs"
          placeholder="feature/login"
          value={branch}
          onChange={(event) => setBranch(event.target.value)}
        />
        <Button
          type="submit"
          size="sm"
          variant="outline"
          disabled={pending || !branch.trim()}
        >
          Scan this branch
        </Button>
        {extraBranches.length > 0 ? (
          <Button
            type="button"
            size="sm"
            variant="ghost"
            disabled={pending}
            onClick={() => void start({ allBranches: true })}
          >
            Rescan all branches
          </Button>
        ) : null}
      </form>
      {message ? (
        <p className="text-text-neutral-secondary text-sm">{message}</p>
      ) : null}
      {error ? (
        <p className="text-text-error-primary text-sm" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
};
