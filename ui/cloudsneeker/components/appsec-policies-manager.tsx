"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  createAppSecPolicy,
  deleteAppSecPolicy,
  getAppSecPolicy,
  updateAppSecPolicy,
  validateAppSecPolicy,
} from "@/cloudsneeker/actions/appsec";
import {
  actionError,
  APPSEC_POLICY_KIND_HELP,
  APPSEC_POLICY_KINDS,
  appSecPolicyKindLabel,
  attributesOf,
  formatAppSecDate,
} from "@/cloudsneeker/lib/appsec";
import {
  FORM_CHECK_CLASS,
  FORM_CHOICE_CLASS,
  FORM_SELECT_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import {
  APPSEC_POLICY_KIND,
  type AppSecPolicyAttributes,
  type AppSecPolicyKind,
  type AppSecPolicyValidation,
  type AppSecResource,
} from "@/cloudsneeker/types/appsec";
import { Button, Input, Textarea } from "@/components/shadcn";
import { Badge } from "@/components/shadcn/badge/badge";

import {
  TABLE_CLASS,
  TABLE_WRAPPER_CLASS,
  TD_CLASS,
  TD_PRIMARY_CLASS,
  TH_CLASS,
} from "./appsec-ui";
import { EmptyState } from "./empty-state";
import { FormActions, FormAlert, FormField } from "./form-layout";
import { SectionCard } from "./section-card";

interface AppSecPoliciesManagerProps {
  policies: AppSecResource<AppSecPolicyAttributes>[];
  canManage: boolean;
}

interface Draft {
  id: string | null;
  kind: AppSecPolicyKind;
  name: string;
  description: string;
  content: string;
  enabled: boolean;
  version: number | null;
}

const EMPTY_DRAFT: Draft = {
  id: null,
  kind: APPSEC_POLICY_KIND.IGNORE_RULES,
  name: "",
  description: "",
  content: "",
  enabled: true,
  version: null,
};

const ValidationResult = ({ result }: { result: AppSecPolicyValidation }) => (
  <div
    role="status"
    className="border-border-neutral-secondary flex flex-col gap-1 rounded-lg border px-3 py-2 text-sm"
  >
    <span className="text-text-neutral-primary font-medium">
      {result.valid ? "The content is valid." : "The content is not valid."}
    </span>
    {(result.errors ?? []).map((message) => (
      <span key={message} className="text-text-error-primary">
        {message}
      </span>
    ))}
    {(result.warnings ?? []).map((message) => (
      <span key={message} className="text-text-neutral-secondary">
        Note: {message}
      </span>
    ))}
  </div>
);

/** Tenant policies passed to scans: checks, secret rules, licenses, ignores, VEX. */
export const AppSecPoliciesManager = ({
  policies,
  canManage,
}: AppSecPoliciesManagerProps) => {
  const router = useRouter();
  const [draft, setDraft] = useState<Draft | null>(null);
  const [validation, setValidation] = useState<AppSecPolicyValidation | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const open = async (policy?: AppSecResource<AppSecPolicyAttributes>) => {
    setError(null);
    setValidation(null);
    if (!policy) {
      setDraft({ ...EMPTY_DRAFT });
      return;
    }
    setBusy(true);
    const detail = attributesOf<AppSecPolicyAttributes>(
      await getAppSecPolicy(policy.id),
    );
    setBusy(false);
    if (!detail) {
      setError("The policy could not be loaded.");
      return;
    }
    setDraft({
      id: policy.id,
      kind: detail.kind,
      name: detail.name,
      description: detail.description,
      content: detail.content ?? "",
      enabled: detail.enabled,
      version: detail.version,
    });
  };

  const close = () => {
    setDraft(null);
    setValidation(null);
    setError(null);
  };

  const onValidate = async () => {
    if (!draft) return;
    setBusy(true);
    setError(null);
    const result = await validateAppSecPolicy(draft.kind, draft.content);
    setBusy(false);
    const failure = actionError(result);
    if (failure) {
      setError(failure);
      return;
    }
    setValidation(attributesOf<AppSecPolicyValidation>(result));
  };

  const onSave = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!draft) return;
    setBusy(true);
    setError(null);
    const attributes = {
      kind: draft.kind,
      name: draft.name.trim(),
      description: draft.description,
      content: draft.content,
      enabled: draft.enabled,
    };
    const result = draft.id
      ? await updateAppSecPolicy(draft.id, attributes)
      : await createAppSecPolicy(attributes);
    setBusy(false);
    const failure = actionError(result);
    if (failure) {
      setError(failure);
      return;
    }
    close();
    router.refresh();
  };

  const onDelete = async () => {
    if (!draft?.id || !window.confirm("Delete this policy?")) return;
    setBusy(true);
    const result = await deleteAppSecPolicy(draft.id);
    setBusy(false);
    const failure = actionError(result);
    if (failure) {
      setError(failure);
      return;
    }
    close();
    router.refresh();
  };

  return (
    <SectionCard
      title="Policies"
      description="Applied to every scan that runs the matching scanner. A scan records which policies it applied and which it skipped."
      actions={
        canManage && !draft ? (
          <Button size="sm" onClick={() => open()}>
            New policy
          </Button>
        ) : null
      }
    >
      {policies.length === 0 && !draft ? (
        <EmptyState
          title="No policies"
          description="Scans use the built-in checks and rules. Add custom checks, secret rules, a license policy, ignore rules or VEX documents here."
        />
      ) : null}
      {policies.length > 0 ? (
        <div className={TABLE_WRAPPER_CLASS}>
          <table className={TABLE_CLASS}>
            <thead>
              <tr>
                <th scope="col" className={TH_CLASS}>
                  Policy
                </th>
                <th scope="col" className={TH_CLASS}>
                  Kind
                </th>
                <th scope="col" className={TH_CLASS}>
                  Version
                </th>
                <th scope="col" className={TH_CLASS}>
                  State
                </th>
                <th scope="col" className={TH_CLASS}>
                  Updated
                </th>
                <th scope="col" className={TH_CLASS}>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {policies.map((policy) => (
                <tr key={policy.id}>
                  <td className={TD_PRIMARY_CLASS}>
                    <span className="font-medium">
                      {policy.attributes.name}
                    </span>
                    <p className="text-text-neutral-secondary text-xs">
                      {policy.attributes.description}
                    </p>
                  </td>
                  <td className={TD_CLASS}>
                    {appSecPolicyKindLabel(policy.attributes.kind)}
                  </td>
                  <td className={TD_CLASS}>{policy.attributes.version}</td>
                  <td className={TD_CLASS}>
                    <Badge
                      variant={policy.attributes.enabled ? "success" : "tag"}
                    >
                      {policy.attributes.enabled ? "Enabled" : "Disabled"}
                    </Badge>
                  </td>
                  <td className={TD_CLASS}>
                    {formatAppSecDate(policy.attributes.updated_at)}
                  </td>
                  <td className={TD_CLASS}>
                    <Button
                      size="xs"
                      variant="outline"
                      disabled={busy}
                      onClick={() => open(policy)}
                    >
                      {canManage ? "Edit" : "View"}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {draft ? (
        <form onSubmit={onSave} className="flex flex-col gap-4" noValidate>
          <h3 className="text-text-neutral-primary text-sm font-semibold">
            {draft.id
              ? `${draft.name} · version ${draft.version}`
              : "New policy"}
          </h3>
          <FormField
            id="policy-kind"
            label="Kind"
            help={APPSEC_POLICY_KIND_HELP[draft.kind]}
          >
            <select
              id="policy-kind"
              className={FORM_SELECT_CLASS}
              value={draft.kind}
              disabled={draft.id !== null}
              onChange={(event) =>
                setDraft({
                  ...draft,
                  kind: event.target.value as AppSecPolicyKind,
                })
              }
            >
              {APPSEC_POLICY_KINDS.map((kind) => (
                <option key={kind} value={kind}>
                  {appSecPolicyKindLabel(kind)}
                </option>
              ))}
            </select>
          </FormField>
          <FormField id="policy-name" label="Name">
            <Input
              id="policy-name"
              value={draft.name}
              maxLength={100}
              onChange={(event) =>
                setDraft({ ...draft, name: event.target.value })
              }
            />
          </FormField>
          <FormField id="policy-description" label="Description" optional>
            <Input
              id="policy-description"
              value={draft.description}
              maxLength={2000}
              onChange={(event) =>
                setDraft({ ...draft, description: event.target.value })
              }
            />
          </FormField>
          <FormField
            id="policy-content"
            label="Content"
            help="Saving changed content creates a new version; the previous one is kept."
          >
            <Textarea
              id="policy-content"
              className="font-mono text-xs"
              rows={14}
              spellCheck={false}
              value={draft.content}
              onChange={(event) => {
                setValidation(null);
                setDraft({ ...draft, content: event.target.value });
              }}
            />
          </FormField>
          <label className={FORM_CHOICE_CLASS}>
            <input
              type="checkbox"
              className={FORM_CHECK_CLASS}
              checked={draft.enabled}
              onChange={(event) =>
                setDraft({ ...draft, enabled: event.target.checked })
              }
            />
            <span>Enabled</span>
          </label>
          {validation ? <ValidationResult result={validation} /> : null}
          <FormAlert message={error} />
          <FormActions>
            {canManage ? (
              <Button type="submit" disabled={busy}>
                {busy ? "Working…" : "Save policy"}
              </Button>
            ) : null}
            <Button
              type="button"
              variant="outline"
              disabled={busy}
              onClick={onValidate}
            >
              Validate
            </Button>
            <Button type="button" variant="ghost" onClick={close}>
              Close
            </Button>
            {canManage && draft.id ? (
              <Button
                type="button"
                variant="destructive"
                disabled={busy}
                onClick={onDelete}
              >
                Delete
              </Button>
            ) : null}
          </FormActions>
        </form>
      ) : (
        <FormAlert message={error} />
      )}
    </SectionCard>
  );
};
