"use client";

import { CheckCircle2, Sparkles, TriangleAlert } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { createCustodianPolicy } from "@/cloudsneeker/actions/custodian";
import {
  generateCustodianPolicyDraft,
  validateCustodianPolicyYaml,
} from "@/cloudsneeker/actions/custodian-library";
import { BRAND } from "@/cloudsneeker/brand";
import {
  FormActions,
  FormAlert,
  FormField,
} from "@/cloudsneeker/components/form-layout";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  actionError,
  draftName,
  GENERATE_EXAMPLES,
  LIBRARY_PROVIDER_LABEL,
  LIBRARY_PROVIDERS,
  readDraft,
  readValidation,
} from "@/cloudsneeker/lib/custodian-library";
import { FORM_CLASS, FORM_SELECT_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { governanceHref } from "@/cloudsneeker/routes";
import {
  LIBRARY_PROVIDER,
  type LibraryProvider,
} from "@/cloudsneeker/types/custodian-library";
import { Button, Input, Textarea } from "@/components/shadcn";

interface ProviderOption {
  id: string;
  label: string;
  providerType: LibraryProvider;
}

interface CustodianPolicyGeneratorProps {
  providers: ProviderOption[];
}

interface Check {
  yaml: string;
  valid: boolean;
  error: string;
}

export const CustodianPolicyGenerator = ({
  providers,
}: CustodianPolicyGeneratorProps) => {
  const router = useRouter();
  const [providerType, setProviderType] = useState<LibraryProvider>(
    providers[0]?.providerType ?? LIBRARY_PROVIDER.AWS,
  );
  const [resourceType, setResourceType] = useState("");
  const [prompt, setPrompt] = useState("");
  const [generating, setGenerating] = useState(false);
  const [checking, setChecking] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasDraft, setHasDraft] = useState(false);
  const [policyYaml, setPolicyYaml] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [providerId, setProviderId] = useState("");
  const [check, setCheck] = useState<Check | null>(null);

  const typeProviders = providers.filter(
    (provider) => provider.providerType === providerType,
  );
  const checkedCurrent = check !== null && check.yaml === policyYaml;
  const canSave =
    checkedCurrent &&
    check.valid &&
    name.trim().length >= 3 &&
    Boolean(providerId) &&
    !saving;

  const chooseProviderType = (value: LibraryProvider) => {
    setProviderType(value);
    setProviderId(
      providers.find((provider) => provider.providerType === value)?.id ?? "",
    );
  };

  const generate = async () => {
    setGenerating(true);
    setError(null);
    const response = await generateCustodianPolicyDraft({
      providerType,
      prompt,
      resourceType: resourceType.trim(),
    });
    setGenerating(false);
    const failure = actionError(response);
    const draft = readDraft(response);
    if (failure || !draft) {
      setError(
        failure ?? `${BRAND.assistantName} returned no draft. Try again.`,
      );
      return;
    }
    setHasDraft(true);
    setPolicyYaml(draft.policy_yaml);
    setName(draftName(draft.name, prompt));
    setDescription(draft.description);
    setProviderId(typeProviders[0]?.id ?? "");
    setCheck({
      yaml: draft.policy_yaml,
      valid: draft.valid,
      error: draft.validation_error,
    });
  };

  const validate = async () => {
    setChecking(true);
    setError(null);
    const yaml = policyYaml;
    const response = await validateCustodianPolicyYaml({
      providerType,
      policyYaml: yaml,
    });
    setChecking(false);
    const failure = actionError(response);
    const result = readValidation(response);
    if (failure || !result) {
      setError(failure ?? "The policy could not be checked. Try again.");
      return;
    }
    setCheck({ yaml, valid: result.valid, error: result.error });
  };

  const save = async () => {
    if (!canSave) return;
    setSaving(true);
    setError(null);
    const result = await createCustodianPolicy({
      name: name.trim(),
      description: description.trim(),
      policyYaml,
      providerId,
    });
    setSaving(false);
    if (result && "error" in result && result.error) {
      setError(
        typeof result.error === "string"
          ? result.error
          : "Failed to save governance policy.",
      );
      return;
    }
    const savedId =
      result && "data" in result && result.data && !Array.isArray(result.data)
        ? (result.data as { id?: string }).id
        : undefined;
    router.push(savedId ? governanceHref(savedId) : governanceHref());
    router.refresh();
  };

  return (
    <div className={FORM_CLASS}>
      <SectionCard
        title="Describe the rule"
        description={`Write what the policy should find in plain language. ${BRAND.assistantName} drafts a dry-run policy and checks it before you can save it.`}
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <FormField id="generate-provider-type" label="Cloud">
            <select
              id="generate-provider-type"
              className={FORM_SELECT_CLASS}
              value={providerType}
              onChange={(event) =>
                chooseProviderType(event.target.value as LibraryProvider)
              }
            >
              {LIBRARY_PROVIDERS.map((item) => (
                <option key={item} value={item}>
                  {LIBRARY_PROVIDER_LABEL[item]}
                </option>
              ))}
            </select>
          </FormField>
          <FormField
            id="generate-resource-type"
            label="Resource type"
            optional
            help={`For example ${providerType}.${providerType === LIBRARY_PROVIDER.AWS ? "s3" : providerType === LIBRARY_PROVIDER.AZURE ? "storage" : "bucket"}. Leave blank to let ${BRAND.assistantName} choose.`}
          >
            <Input
              id="generate-resource-type"
              className="font-mono text-sm"
              value={resourceType}
              onChange={(event) => setResourceType(event.target.value)}
            />
          </FormField>
        </div>
        <FormField
          id="generate-prompt"
          label="What should the policy find?"
          help="At least 10 characters."
        >
          <Textarea
            id="generate-prompt"
            className="min-h-28"
            maxLength={2000}
            value={prompt}
            onChange={(event) => setPrompt(event.target.value)}
          />
        </FormField>
        <div className="flex flex-wrap gap-2">
          {GENERATE_EXAMPLES[providerType].map((example) => (
            <Button
              key={example}
              type="button"
              size="xs"
              variant="outline"
              onClick={() => setPrompt(example)}
            >
              {example}
            </Button>
          ))}
        </div>
        <div>
          <Button
            type="button"
            disabled={generating || prompt.trim().length < 10}
            onClick={generate}
          >
            <Sparkles aria-hidden="true" />
            {generating
              ? `${BRAND.assistantName} is drafting…`
              : `Generate with ${BRAND.assistantName}`}
          </Button>
        </div>
      </SectionCard>

      {hasDraft ? (
        <SectionCard
          title="Review the draft"
          description="Edit anything you like. The policy is checked again before it can be saved, and it only ever runs as a dry-run."
        >
          {checkedCurrent ? (
            check.valid ? (
              <p
                role="status"
                className="text-text-success-primary flex items-center gap-2 text-sm"
              >
                <CheckCircle2 className="size-4" aria-hidden="true" />
                The policy passed validation.
              </p>
            ) : (
              <p
                role="alert"
                className="text-text-error-primary flex items-start gap-2 text-sm"
              >
                <TriangleAlert
                  className="mt-0.5 size-4 shrink-0"
                  aria-hidden="true"
                />
                <span>Validation failed: {check.error}</span>
              </p>
            )
          ) : (
            <p className="text-text-neutral-secondary text-sm" role="status">
              The YAML changed. Check it again before saving.
            </p>
          )}

          <div className="grid gap-4 sm:grid-cols-2">
            <FormField id="draft-name" label="Policy name">
              <Input
                id="draft-name"
                maxLength={100}
                value={name}
                onChange={(event) => setName(event.target.value)}
              />
            </FormField>
            <FormField id="draft-provider" label="Provider">
              <select
                id="draft-provider"
                className={FORM_SELECT_CLASS}
                value={providerId}
                onChange={(event) => setProviderId(event.target.value)}
              >
                {typeProviders.length === 0 ? (
                  <option value="">
                    No {LIBRARY_PROVIDER_LABEL[providerType]} provider connected
                  </option>
                ) : (
                  typeProviders.map((provider) => (
                    <option key={provider.id} value={provider.id}>
                      {provider.label}
                    </option>
                  ))
                )}
              </select>
            </FormField>
          </div>
          <FormField id="draft-description" label="Description" optional>
            <Input
              id="draft-description"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
            />
          </FormField>
          <FormField id="draft-yaml" label="Policy YAML">
            <Textarea
              id="draft-yaml"
              className="min-h-64 font-mono text-sm"
              spellCheck={false}
              value={policyYaml}
              onChange={(event) => setPolicyYaml(event.target.value)}
            />
          </FormField>
        </SectionCard>
      ) : null}

      <FormAlert message={error} />

      <FormActions>
        <Button
          type="button"
          variant="ghost"
          onClick={() => router.push(governanceHref())}
        >
          Cancel
        </Button>
        {hasDraft ? (
          <>
            <Button
              type="button"
              variant="outline"
              disabled={checking || checkedCurrent}
              onClick={validate}
            >
              {checking ? "Checking…" : "Check policy"}
            </Button>
            <Button type="button" disabled={!canSave} onClick={save}>
              {saving ? "Saving…" : "Save policy"}
            </Button>
          </>
        ) : null}
      </FormActions>
    </div>
  );
};
