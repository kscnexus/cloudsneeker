"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { mergeTrivyTargets } from "@/cloudsneeker/actions/trivy";
import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
import {
  FORM_CHECK_CLASS,
  FORM_CHOICE_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import type { TrivyMode } from "@/cloudsneeker/types/trivy";
import { Button } from "@/components/shadcn";

export interface MergeCandidate {
  id: string;
  name: string;
  mode: TrivyMode;
  branch: string;
}

interface TargetMergePanelProps {
  targetId: string;
  candidates: MergeCandidate[];
}

/**
 * Fold the other targets of the same repository into this one: static
 * analysis targets turn static analysis on here, other-branch targets
 * become extra branches. Findings, runs and triage move with them.
 */
export const TargetMergePanel = ({
  targetId,
  candidates,
}: TargetMergePanelProps) => {
  const router = useRouter();
  const [selected, setSelected] = useState<string[]>(
    candidates.map((item) => item.id),
  );
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggle = (id: string) =>
    setSelected((current) =>
      current.includes(id)
        ? current.filter((item) => item !== id)
        : [...current, id],
    );

  const onMerge = async () => {
    setPending(true);
    setError(null);
    const result = await mergeTrivyTargets(targetId, selected);
    setPending(false);
    if (result && typeof result === "object" && "error" in result) {
      const value = (result as { error?: unknown }).error;
      if (value) {
        setError(typeof value === "string" ? value : "Merge failed.");
        return;
      }
    }
    router.refresh();
  };

  return (
    <div className="flex flex-col gap-3">
      <ul className="flex flex-col gap-2">
        {candidates.map((item) => (
          <li key={item.id}>
            <label htmlFor={`merge-${item.id}`} className={FORM_CHOICE_CLASS}>
              <input
                id={`merge-${item.id}`}
                type="checkbox"
                className={FORM_CHECK_CLASS}
                checked={selected.includes(item.id)}
                onChange={() => toggle(item.id)}
              />
              <span className="flex min-w-0 flex-col">
                {item.name}
                <span className="text-text-neutral-tertiary text-xs">
                  {labelForTrivyMode(item.mode)}
                  {item.branch ? ` · ${item.branch}` : " · default branch"}
                </span>
              </span>
            </label>
          </li>
        ))}
      </ul>
      <div className="flex items-center gap-3">
        <Button
          type="button"
          size="sm"
          disabled={pending || selected.length === 0}
          onClick={() => void onMerge()}
        >
          {pending ? "Merging…" : `Merge ${selected.length} into this target`}
        </Button>
        {error ? (
          <span className="text-text-error-primary text-sm" role="alert">
            {error}
          </span>
        ) : null}
      </div>
    </div>
  );
};
