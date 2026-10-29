"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter } from "next/navigation";
import { useState, type ChangeEvent } from "react";
import { useForm, useWatch } from "react-hook-form";

import {
  createTrivyTarget,
  updateTrivyTarget,
} from "@/cloudsneeker/actions/trivy";
import {
  FormActions,
  FormAlert,
  FormChoiceGroup,
  FormField,
} from "@/cloudsneeker/components/form-layout";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  buildTrivyConfig,
  CODE_ARCHIVE_ACCEPT,
  CODE_ARCHIVE_HELP,
  isSupportedCodeArchive,
  SAST_SOURCE,
  toggleSastRuleset,
  trivyTargetFormSchema,
  type TrivyTargetFormInput,
  type TrivyTargetFormValues,
} from "@/cloudsneeker/lib/trivy-form-schema";
import {
  SAST_RULESET_OPTIONS,
  TRIVY_MODE_OPTIONS,
  providerTypesForMode,
} from "@/cloudsneeker/lib/trivy-modes";
import {
  FORM_CHECK_CLASS,
  FORM_CHOICE_CLASS,
  FORM_CLASS,
  FORM_SELECT_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import {
  SAST_RULESET,
  type SastRuleset,
  TRIVY_MODE,
  type TrivyMode,
} from "@/cloudsneeker/types/trivy";
import { Button, Input, Textarea } from "@/components/shadcn";

const SAST_SOURCE_OPTIONS = [
  { value: SAST_SOURCE.REPOSITORY, label: "Git repository" },
  { value: SAST_SOURCE.ARCHIVE, label: "Upload code archive" },
] as const;

const EXCLUDE_PLACEHOLDER = ["tests/**", "**/*.min.js"].join("\n");

interface ProviderOption {
  id: string;
  label: string;
  providerType?: string;
}

interface TrivyTargetFormProps {
  providers: ProviderOption[];
  initialValues?: TrivyTargetFormInput;
  targetId?: string;
}

export const TrivyTargetForm = ({
  providers,
  initialValues,
  targetId,
}: TrivyTargetFormProps) => {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const form = useForm<TrivyTargetFormInput, unknown, TrivyTargetFormValues>({
    resolver: zodResolver(trivyTargetFormSchema),
    defaultValues: initialValues ?? {
      name: "",
      description: "",
      mode: TRIVY_MODE.IAC,
      providerId: providers[0]?.id ?? "",
      scanners: "vuln,misconfig,secret",
      images: "",
      repositoryUrl: "",
      archiveB64: "",
      sbom: "",
      namespace: "",
      sastSource: SAST_SOURCE.REPOSITORY,
      rulesets: [SAST_RULESET.AUTO],
      exclude: "",
      scheduleEnabled: false,
      scheduleCron: "",
      scheduleTimezone: "UTC",
    },
  });

  const mode = useWatch({ control: form.control, name: "mode" }) as TrivyMode;
  const scheduleEnabled = useWatch({
    control: form.control,
    name: "scheduleEnabled",
  });
  const sastSource = useWatch({ control: form.control, name: "sastSource" });
  const rulesets: SastRuleset[] =
    useWatch({ control: form.control, name: "rulesets" }) ?? [];
  const toggleRuleset = (value: SastRuleset) =>
    form.setValue("rulesets", toggleSastRuleset(rulesets, value), {
      shouldDirty: true,
      shouldValidate: true,
    });
  const requiredTypes = providerTypesForMode(mode);
  const filteredProviders =
    requiredTypes.length === 0
      ? providers
      : providers.filter((provider) =>
          requiredTypes.includes(provider.providerType ?? ""),
        );

  const onSubmit = form.handleSubmit(async (values) => {
    setSaving(true);
    setError(null);
    const payload = {
      name: values.name,
      description: values.description,
      mode: values.mode,
      providerId: values.providerId,
      config: buildTrivyConfig(values),
      scheduleEnabled: values.scheduleEnabled,
      scheduleCron: values.scheduleEnabled ? values.scheduleCron : "",
      scheduleTimezone: values.scheduleTimezone || "UTC",
    };
    const result = targetId
      ? await updateTrivyTarget(targetId, payload)
      : await createTrivyTarget(payload);
    setSaving(false);
    if (result && "error" in result && result.error) {
      setError(
        typeof result.error === "string"
          ? result.error
          : "Failed to save target.",
      );
      return;
    }
    const id = targetId || result?.data?.id;
    router.push(id ? appSecurityHref(id) : appSecurityHref());
    router.refresh();
  });

  const onArchiveSelected = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    if (!isSupportedCodeArchive(file.name)) {
      // 7-Zip, RAR and other formats fail later in the scan worker.
      event.target.value = "";
      form.setValue("archiveB64", "");
      form.setError("archiveB64", {
        type: "manual",
        message: CODE_ARCHIVE_HELP,
      });
      return;
    }
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let index = 0; index < bytes.length; index += 1) {
      binary += String.fromCharCode(bytes[index]);
    }
    form.setValue("archiveB64", btoa(binary), { shouldValidate: true });
  };

  const errors = form.formState.errors;
  const archiveHelp = targetId
    ? `${CODE_ARCHIVE_HELP}. Upload the archive again to replace the stored code.`
    : CODE_ARCHIVE_HELP;
  const modeDescription = TRIVY_MODE_OPTIONS.find(
    (option) => option.value === mode,
  )?.description;

  return (
    <form onSubmit={onSubmit} className={FORM_CLASS}>
      <SectionCard
        title="Target"
        description="How this target appears in lists and reports."
      >
        <FormField id="trivy-name" label="Name" error={errors.name?.message}>
          <Input id="trivy-name" {...form.register("name")} />
        </FormField>
        <FormField
          id="trivy-description"
          label="Description"
          optional
          error={errors.description?.message}
        >
          <Textarea
            id="trivy-description"
            rows={2}
            {...form.register("description")}
          />
        </FormField>
      </SectionCard>

      <SectionCard
        title="What to scan"
        description="Choose the scan type and the connected source it reads."
      >
        <FormField
          id="trivy-mode"
          label="Mode"
          help={modeDescription}
          error={errors.mode?.message}
        >
          <select
            id="trivy-mode"
            className={FORM_SELECT_CLASS}
            {...form.register("mode")}
          >
            {TRIVY_MODE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </FormField>

        <FormField
          id="trivy-provider"
          label="Provider"
          help={
            requiredTypes.length > 0
              ? `Requires a ${requiredTypes.join(" / ")} provider. Create one under Providers if the list is empty.`
              : "Findings attach to the selected provider account."
          }
          error={errors.providerId?.message}
        >
          <select
            id="trivy-provider"
            className={FORM_SELECT_CLASS}
            {...form.register("providerId")}
          >
            {filteredProviders.length === 0 ? (
              <option value="">No matching providers</option>
            ) : (
              filteredProviders.map((provider) => (
                <option key={provider.id} value={provider.id}>
                  {provider.label}
                </option>
              ))
            )}
          </select>
        </FormField>

        {mode !== TRIVY_MODE.SAST ? (
          <FormField
            id="trivy-scanners"
            label="Scanners"
            help="Comma-separated, for example vuln,misconfig,secret."
            error={errors.scanners?.message}
          >
            <Input id="trivy-scanners" {...form.register("scanners")} />
          </FormField>
        ) : null}

        {mode === TRIVY_MODE.IMAGE ? (
          <FormField
            id="trivy-images"
            label="Images"
            help="One image reference per line."
            error={errors.images?.message}
          >
            <Textarea id="trivy-images" rows={3} {...form.register("images")} />
          </FormField>
        ) : null}

        {mode === TRIVY_MODE.REPO ? (
          <FormField
            id="trivy-repo"
            label="Repository URL"
            error={errors.repositoryUrl?.message}
          >
            <Input
              id="trivy-repo"
              placeholder="https://github.com/acme/app"
              {...form.register("repositoryUrl")}
            />
          </FormField>
        ) : null}

        {mode === TRIVY_MODE.FS ? (
          <FormField
            id="trivy-archive"
            label="Code archive"
            help={archiveHelp}
            error={errors.archiveB64?.message}
          >
            <Input
              id="trivy-archive"
              type="file"
              accept={CODE_ARCHIVE_ACCEPT}
              onChange={onArchiveSelected}
            />
          </FormField>
        ) : null}

        {mode === TRIVY_MODE.SBOM ? (
          <FormField
            id="trivy-sbom"
            label="SBOM content"
            help="Paste a CycloneDX or SPDX document."
            error={errors.sbom?.message}
          >
            <Textarea
              id="trivy-sbom"
              rows={8}
              className="font-mono text-xs"
              {...form.register("sbom")}
            />
          </FormField>
        ) : null}

        {mode === TRIVY_MODE.K8S ? (
          <FormField
            id="trivy-namespace"
            label="Namespace"
            optional
            help="Leave blank to scan every namespace."
            error={errors.namespace?.message}
          >
            <Input id="trivy-namespace" {...form.register("namespace")} />
          </FormField>
        ) : null}
      </SectionCard>

      {mode === TRIVY_MODE.SAST ? (
        <SectionCard
          title="Source code"
          description="Where the code comes from and which rule packs run."
        >
          <FormChoiceGroup legend="Source">
            <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:gap-4">
              {SAST_SOURCE_OPTIONS.map((option) => (
                <label
                  key={option.value}
                  htmlFor={`trivy-sast-source-${option.value}`}
                  className={FORM_CHOICE_CLASS}
                >
                  <input
                    id={`trivy-sast-source-${option.value}`}
                    type="radio"
                    value={option.value}
                    className={FORM_CHECK_CLASS}
                    {...form.register("sastSource")}
                  />
                  {option.label}
                </label>
              ))}
            </div>
          </FormChoiceGroup>

          {sastSource === SAST_SOURCE.ARCHIVE ? (
            <FormField
              id="trivy-sast-archive"
              label="Code archive"
              help={archiveHelp}
              error={errors.archiveB64?.message}
            >
              <Input
                id="trivy-sast-archive"
                type="file"
                accept={CODE_ARCHIVE_ACCEPT}
                onChange={onArchiveSelected}
              />
            </FormField>
          ) : (
            <FormField
              id="trivy-sast-repo"
              label="Repository URL"
              help="Use the repository saved on the selected source. Access tokens stay on the source, never in the URL."
              error={errors.repositoryUrl?.message}
            >
              <Input
                id="trivy-sast-repo"
                placeholder="https://github.com/acme/app"
                {...form.register("repositoryUrl")}
              />
            </FormField>
          )}

          <FormChoiceGroup legend="Rule packs" error={errors.rulesets?.message}>
            <div className="grid gap-2 sm:grid-cols-2">
              {SAST_RULESET_OPTIONS.map((option) => (
                <label
                  key={option.value}
                  htmlFor={`trivy-sast-ruleset-${option.value}`}
                  className={FORM_CHOICE_CLASS}
                >
                  <input
                    id={`trivy-sast-ruleset-${option.value}`}
                    type="checkbox"
                    className={FORM_CHECK_CLASS}
                    checked={rulesets.includes(option.value)}
                    onChange={() => toggleRuleset(option.value)}
                  />
                  <span className="flex min-w-0 flex-col">
                    {option.label}
                    {option.description ? (
                      <span className="text-text-neutral-tertiary text-xs">
                        {option.description}
                      </span>
                    ) : null}
                  </span>
                </label>
              ))}
            </div>
          </FormChoiceGroup>

          <FormField
            id="trivy-sast-exclude"
            label="Exclude paths"
            optional
            help="One glob per line."
            error={errors.exclude?.message}
          >
            <Textarea
              id="trivy-sast-exclude"
              rows={3}
              className="font-mono text-xs"
              placeholder={EXCLUDE_PLACEHOLDER}
              {...form.register("exclude")}
            />
          </FormField>
        </SectionCard>
      ) : null}

      <SectionCard
        title="Schedule"
        description="Run this target automatically. Leave it off to scan on demand."
      >
        <label htmlFor="trivy-schedule-enabled" className={FORM_CHOICE_CLASS}>
          <input
            id="trivy-schedule-enabled"
            type="checkbox"
            className={FORM_CHECK_CLASS}
            {...form.register("scheduleEnabled")}
          />
          Enable schedule
        </label>

        {scheduleEnabled ? (
          <div className="grid gap-4 sm:grid-cols-2">
            <FormField
              id="trivy-cron"
              label="Cron"
              help="Five fields: minute hour day month weekday."
              error={errors.scheduleCron?.message}
            >
              <Input
                id="trivy-cron"
                className="font-mono"
                placeholder="0 9 * * 1"
                {...form.register("scheduleCron")}
              />
            </FormField>
            <FormField
              id="trivy-tz"
              label="Timezone"
              error={errors.scheduleTimezone?.message}
            >
              <Input
                id="trivy-tz"
                placeholder="UTC"
                {...form.register("scheduleTimezone")}
              />
            </FormField>
          </div>
        ) : null}
      </SectionCard>

      <FormAlert message={error} />

      <FormActions>
        <Button
          type="button"
          variant="ghost"
          onClick={() =>
            router.push(
              targetId ? appSecurityHref(targetId) : appSecurityHref(),
            )
          }
        >
          Cancel
        </Button>
        <Button
          type="submit"
          disabled={saving || filteredProviders.length === 0}
        >
          {saving ? "Saving…" : targetId ? "Save changes" : "Create target"}
        </Button>
      </FormActions>
    </form>
  );
};
