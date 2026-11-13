"use client";

import { useEffect, useState, type ChangeEvent } from "react";

import { listRepositoryBranches } from "@/cloudsneeker/actions/appsec";
import { FormField } from "@/cloudsneeker/components/form-layout";
import { toRepositoryBranchList } from "@/cloudsneeker/lib/repository-branches";
import { FORM_SELECT_CLASS } from "@/cloudsneeker/lib/ui-classes";
import type { RepositoryBranchList } from "@/cloudsneeker/types/trivy";
import { Input } from "@/components/shadcn";
import {
  MultiSelect,
  MultiSelectContent,
  MultiSelectItem,
  MultiSelectTrigger,
  MultiSelectValue,
} from "@/components/shadcn/select/multiselect";

const LOAD_STATE = {
  IDLE: "idle",
  LOADED: "loaded",
  FAILED: "failed",
} as const;

type LoadState = (typeof LOAD_STATE)[keyof typeof LOAD_STATE];

interface BranchLoad {
  providerId: string;
  state: LoadState;
  list: RepositoryBranchList | null;
  message: string;
}

interface RepositoryBranchFieldProps {
  id: string;
  /** Source whose repository is listed; empty shows nothing to pick. */
  providerId: string;
  value: string[];
  onChange: (branches: string[]) => void;
  /** Allow several branches (a new target); otherwise one (an edit). */
  multiple: boolean;
  error?: string;
}

const splitBranches = (text: string): string[] =>
  Array.from(
    new Set(
      text
        .split(/[\n,]/)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  );

const defaultLabel = (list: RepositoryBranchList | null): string =>
  list?.defaultBranch
    ? `Default branch (${list.defaultBranch})`
    : "Default branch";

export const RepositoryBranchField = ({
  id,
  providerId,
  value,
  onChange,
  multiple,
  error,
}: RepositoryBranchFieldProps) => {
  const [load, setLoad] = useState<BranchLoad>({
    providerId: "",
    state: LOAD_STATE.IDLE,
    list: null,
    message: "",
  });

  useEffect(() => {
    if (!providerId) return;
    let cancelled = false;
    // Until the response for this source arrives, `current` is null: loading.
    listRepositoryBranches(providerId).then(
      (response) => {
        if (cancelled) return;
        const list = toRepositoryBranchList(response);
        if (list) {
          setLoad({ providerId, state: LOAD_STATE.LOADED, list, message: "" });
          return;
        }
        const message =
          response && typeof response === "object" && "error" in response
            ? String(response.error)
            : "The branches could not be listed.";
        setLoad({ providerId, state: LOAD_STATE.FAILED, list: null, message });
      },
      () => {
        if (cancelled) return;
        setLoad({
          providerId,
          state: LOAD_STATE.FAILED,
          list: null,
          message: "The branches could not be listed.",
        });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [providerId]);

  const current = load.providerId === providerId ? load : null;
  const list = current?.state === LOAD_STATE.LOADED ? current.list : null;
  // Keep saved branches selectable even if the listing no longer has them.
  const options = Array.from(new Set([...(list?.branches ?? []), ...value]));
  const help = multiple
    ? "Leave empty to scan the default branch. Each branch you pick becomes its own target, with its own scans, schedule and reports."
    : "Changes apply from the next scan.";

  if (!providerId) return null;

  if (current?.state === LOAD_STATE.FAILED) {
    return (
      <FormField
        id={id}
        label={multiple ? "Branches" : "Branch"}
        optional
        help={`${current.message} Type the branch ${multiple ? "names, one per line or comma-separated" : "name"}; leave empty for the default branch.`}
        error={error}
      >
        <Input
          id={id}
          defaultValue={value.join(multiple ? ", " : "")}
          placeholder="main"
          onChange={(event: ChangeEvent<HTMLInputElement>) =>
            onChange(
              splitBranches(event.target.value).slice(
                0,
                multiple ? undefined : 1,
              ),
            )
          }
        />
      </FormField>
    );
  }

  if (!list) {
    return (
      <FormField id={id} label={multiple ? "Branches" : "Branch"} optional>
        <p id={id} role="status" className="text-text-neutral-tertiary text-sm">
          Loading branches…
        </p>
      </FormField>
    );
  }

  const truncatedHelp = list.truncated
    ? " Only the first branches are listed."
    : "";

  if (!multiple) {
    return (
      <FormField
        id={id}
        label="Branch"
        optional
        help={`${help}${truncatedHelp}`}
        error={error}
      >
        <select
          id={id}
          className={FORM_SELECT_CLASS}
          value={value[0] ?? ""}
          onChange={(event) =>
            onChange(event.target.value ? [event.target.value] : [])
          }
        >
          <option value="">{defaultLabel(list)}</option>
          {options.map((branch) => (
            <option key={branch} value={branch}>
              {branch}
            </option>
          ))}
        </select>
      </FormField>
    );
  }

  return (
    <FormField
      id={id}
      label="Branches"
      optional
      help={`${help}${truncatedHelp}`}
      error={error}
    >
      <MultiSelect values={value} onValuesChange={onChange}>
        <MultiSelectTrigger id={id} aria-label="Branches">
          <MultiSelectValue placeholder={defaultLabel(list)} />
        </MultiSelectTrigger>
        <MultiSelectContent
          search={{
            placeholder: "Search branches",
            emptyMessage: "No branch matches.",
          }}
        >
          {options.map((branch) => (
            <MultiSelectItem
              key={branch}
              value={branch}
              badgeLabel={branch}
              keywords={[branch]}
            >
              {branch}
              {branch === list.defaultBranch ? (
                <span className="text-text-neutral-tertiary text-xs">
                  default
                </span>
              ) : null}
            </MultiSelectItem>
          ))}
        </MultiSelectContent>
      </MultiSelect>
    </FormField>
  );
};
