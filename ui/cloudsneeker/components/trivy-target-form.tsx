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
  buildTrivyConfig,
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
import { appSecurityHref } from "@/cloudsneeker/routes";
import {
  SAST_RULESET,
  type SastRuleset,
  TRIVY_MODE,
  type TrivyMode,
} from "@/cloudsneeker/types/trivy";
import { Button, Input, Label, Textarea } from "@/components/shadcn";

const SAST_SOURCE_OPTIONS = [
  { value: SAST_SOURCE.REPOSITORY, label: "Git repository" },
  { value: SAST_SOURCE.ARCHIVE, label: "Upload code archive" },
] as const;

const FieldError = ({ message }: { message?: string }) =>
  message ? <p className="text-text-error-primary text-xs">{message}</p> : null;

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

  const form = useForm<
    TrivyTargetFormInput,
    unknown,
    TrivyTargetFormValues
  >({
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

  const onArchiveSelected = async (
    event: ChangeEvent<HTMLInputElement>,
  ) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let index = 0; index < bytes.length; index += 1) {
      binary += String.fromCharCode(bytes[index]);
    }
    form.setValue("archiveB64", btoa(binary), { shouldValidate: true });
  };

  return (
    <form onSubmit={onSubmit} className="flex max-w-2xl flex-col gap-4">
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="trivy-name">Name</Label>
        <Input id="trivy-name" {...form.register("name")} />
      </div>

      <div className="flex flex-col gap-1.5">
        <Label htmlFor="trivy-description">Description</Label>
        <Textarea id="trivy-description" rows={2} {...form.register("description")} />
      </div>

      <div className="flex flex-col gap-1.5">
        <Label htmlFor="trivy-mode">Mode</Label>
        <select
          id="trivy-mode"
          className="border-border-neutral-secondary bg-bg-neutral-primary text-text-neutral-primary rounded-md border px-3 py-2 text-sm"
          {...form.register("mode")}
        >
          {TRIVY_MODE_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        <p className="text-text-neutral-secondary text-xs">
          {
            TRIVY_MODE_OPTIONS.find((option) => option.value === mode)
              ?.description
          }
        </p>
      </div>

      <div className="flex flex-col gap-1.5">
        <Label htmlFor="trivy-provider">Provider</Label>
        <select
          id="trivy-provider"
          className="border-border-neutral-secondary bg-bg-neutral-primary text-text-neutral-primary rounded-md border px-3 py-2 text-sm"
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
        {requiredTypes.length > 0 ? (
          <p className="text-text-neutral-secondary text-xs">
            Requires a {requiredTypes.join(" / ")} provider. Create one under
            Providers if the list is empty.
          </p>
        ) : (
          <p className="text-text-neutral-secondary text-xs">
            Findings attach to the selected provider account.
          </p>
        )}
      </div>

      {mode !== TRIVY_MODE.SAST ? (
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="trivy-scanners">Scanners (comma-separated)</Label>
          <Input id="trivy-scanners" {...form.register("scanners")} />
        </div>
      ) : null}

      {mode === TRIVY_MODE.SAST ? (
        <fieldset className="border-border-neutral-secondary flex flex-col gap-4 rounded-xl border p-4">
          <legend className="text-text-neutral-primary px-1 text-sm font-semibold">
            Source code
          </legend>
          <div className="flex flex-wrap gap-4">
            {SAST_SOURCE_OPTIONS.map((option) => (
              <label
                key={option.value}
                htmlFor={`trivy-sast-source-${option.value}`}
                className="text-text-neutral-primary flex items-center gap-2 text-sm"
              >
                <input
                  id={`trivy-sast-source-${option.value}`}
                  type="radio"
                  value={option.value}
                  className="size-4"
                  {...form.register("sastSource")}
                />
                {option.label}
              </label>
            ))}
          </div>

          {sastSource === SAST_SOURCE.ARCHIVE ? (
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="trivy-sast-archive">Code archive (zip or tar)</Label>
              <Input
                id="trivy-sast-archive"
                type="file"
                accept=".zip,.tar,.tar.gz,.tgz"
                onChange={onArchiveSelected}
              />
              {targetId ? (
                <p className="text-text-neutral-secondary text-xs">
                  Upload the archive again to replace the stored code.
                </p>
              ) : null}
              <FieldError message={form.formState.errors.archiveB64?.message} />
            </div>
          ) : (
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="trivy-sast-repo">Repository URL</Label>
              <Input
                id="trivy-sast-repo"
                placeholder="https://github.com/acme/app"
                {...form.register("repositoryUrl")}
              />
              <p className="text-text-neutral-secondary text-xs">
                Use the repository saved on the selected source. Access tokens
                stay on the source, never in the URL.
              </p>
              <FieldError
                message={form.formState.errors.repositoryUrl?.message}
              />
            </div>
          )}

          <div className="flex flex-col gap-2">
            <span className="text-text-neutral-primary text-sm font-medium">
              Rule packs
            </span>
            <div className="grid gap-2 sm:grid-cols-2">
              {SAST_RULESET_OPTIONS.map((option) => (
                <label
                  key={option.value}
                  htmlFor={`trivy-sast-ruleset-${option.value}`}
                  className="text-text-neutral-primary flex items-start gap-2 text-sm"
                >
                  <input
                    id={`trivy-sast-ruleset-${option.value}`}
                    type="checkbox"
                    className="mt-0.5 size-4"
                    checked={rulesets.includes(option.value)}
                    onChange={() => toggleRuleset(option.value)}
                  />
                  <span className="flex flex-col">
                    {option.label}
                    {option.description ? (
                      <span className="text-text-neutral-secondary text-xs">
                        {option.description}
                      </span>
                    ) : null}
                  </span>
                </label>
              ))}
            </div>
            <FieldError message={form.formState.errors.rulesets?.message} />
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="trivy-sast-exclude">Exclude paths (one glob per line)</Label>
            <Textarea
              id="trivy-sast-exclude"
              rows={3}
              placeholder={"tests/**\n**/*.min.js"}
              {...form.register("exclude")}
            />
            <FieldError message={form.formState.errors.exclude?.message} />
          </div>
        </fieldset>
      ) : null}

      {mode === TRIVY_MODE.IMAGE ? (
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="trivy-images">Images (one per line)</Label>
          <Textarea id="trivy-images" rows={3} {...form.register("images")} />
        </div>
      ) : null}

      {mode === TRIVY_MODE.REPO ? (
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="trivy-repo">Repository URL</Label>
          <Input id="trivy-repo" {...form.register("repositoryUrl")} />
        </div>
      ) : null}

      {mode === TRIVY_MODE.FS ? (
        <>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="trivy-archive">Archive (zip or tar)</Label>
            <Input
              id="trivy-archive"
              type="file"
              accept=".zip,.tar,.tar.gz,.tgz"
              onChange={onArchiveSelected}
            />
          </div>
        </>
      ) : null}

      {mode === TRIVY_MODE.SBOM ? (
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="trivy-sbom">SBOM content</Label>
          <Textarea id="trivy-sbom" rows={8} {...form.register("sbom")} />
        </div>
      ) : null}

      {mode === TRIVY_MODE.K8S ? (
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="trivy-namespace">Namespace (optional)</Label>
          <Input id="trivy-namespace" {...form.register("namespace")} />
        </div>
      ) : null}

      <div className="flex items-center gap-2">
        <input
          id="trivy-schedule-enabled"
          type="checkbox"
          className="size-4"
          {...form.register("scheduleEnabled")}
        />
        <Label htmlFor="trivy-schedule-enabled">Enable schedule</Label>
      </div>

      {scheduleEnabled ? (
        <>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="trivy-cron">Cron (5 fields)</Label>
            <Input
              id="trivy-cron"
              placeholder="0 9 * * 1"
              {...form.register("scheduleCron")}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="trivy-tz">Timezone</Label>
            <Input id="trivy-tz" {...form.register("scheduleTimezone")} />
          </div>
        </>
      ) : null}

      {error ? (
        <p className="text-text-error-primary text-sm">{error}</p>
      ) : null}

      <div className="flex gap-2">
        <Button type="submit" disabled={saving || filteredProviders.length === 0}>
          {saving ? "Saving…" : targetId ? "Save changes" : "Create target"}
        </Button>
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
      </div>
    </form>
  );
};
