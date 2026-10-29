"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useForm, useWatch } from "react-hook-form";

import {
  createCustodianPolicy,
  installCustodianPack,
  updateCustodianPolicy,
} from "@/cloudsneeker/actions/custodian";
import {
  CUSTODIAN_BUILDER_RESOURCE,
  CUSTODIAN_BUILDER_RESOURCES,
  buildCustodianPolicyYaml,
  filtersForResource,
  type CustodianBuilderResource,
} from "@/cloudsneeker/lib/custodian-builder";
import {
  custodianPolicyFormSchema,
  type CustodianPolicyFormInput,
  type CustodianPolicyFormValues,
} from "@/cloudsneeker/lib/custodian-form-schema";
import { CUSTODIAN_SCHEDULE_PRESET } from "@/cloudsneeker/lib/custodian-schedule";
import {
  packsForProvider,
  templatesForProvider,
} from "@/cloudsneeker/lib/custodian-templates";
import { governanceHref } from "@/cloudsneeker/routes";
import { Button, Input, Label, Textarea } from "@/components/shadcn";

interface ProviderOption {
  id: string;
  label: string;
  providerType?: string;
}

interface CustodianPolicyFormProps {
  providers: ProviderOption[];
  initialValues?: CustodianPolicyFormInput;
  policyId?: string;
}

const WEEKDAYS = [
  { value: 0, label: "Sunday" },
  { value: 1, label: "Monday" },
  { value: 2, label: "Tuesday" },
  { value: 3, label: "Wednesday" },
  { value: 4, label: "Thursday" },
  { value: 5, label: "Friday" },
  { value: 6, label: "Saturday" },
] as const;

export const CustodianPolicyForm = ({
  providers,
  initialValues,
  policyId,
}: CustodianPolicyFormProps) => {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [builderResource, setBuilderResource] =
    useState<CustodianBuilderResource>(CUSTODIAN_BUILDER_RESOURCE.AWS_EBS);
  const [builderFilters, setBuilderFilters] = useState<string[]>(["unattached"]);
  const [packMessage, setPackMessage] = useState<string | null>(null);

  const form = useForm<
    CustodianPolicyFormInput,
    unknown,
    CustodianPolicyFormValues
  >({
    resolver: zodResolver(custodianPolicyFormSchema),
    defaultValues: initialValues ?? {
      name: "",
      description: "",
      providerId: providers[0]?.id ?? "",
      policyYaml: `policies:
  - name: example-unused-ebs
    resource: aws.ebs
    filters:
      - Attachments: []
`,
      schedulePreset: CUSTODIAN_SCHEDULE_PRESET.DISABLED,
      scheduleHour: 9,
      scheduleWeekday: 1,
      scheduleTimezone: "UTC",
      scheduleCron: "",
      regionsOverride: "",
    },
  });

  const schedulePreset = useWatch({
    control: form.control,
    name: "schedulePreset",
  });
  const providerId = useWatch({
    control: form.control,
    name: "providerId",
  });
  const selectedProvider = providers.find((item) => item.id === providerId);
  const templates = templatesForProvider(selectedProvider?.providerType);
  const packs = packsForProvider(selectedProvider?.providerType);
  const builderFilterOptions = filtersForResource(builderResource);

  const onSubmit = form.handleSubmit(async (values) => {
    setSaving(true);
    setError(null);
    const payload = {
      name: values.name,
      description: values.description ?? "",
      policyYaml: values.policyYaml,
      providerId: values.providerId,
      scheduleEnabled: values.scheduleEnabled,
      scheduleCron: values.scheduleCron,
      scheduleTimezone: values.scheduleTimezone,
      regionsOverride: values.regionsOverrideList,
    };
    const result = policyId
      ? await updateCustodianPolicy(policyId, payload)
      : await createCustodianPolicy(payload);

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
      policyId ??
      (result && "data" in result && result.data && !Array.isArray(result.data)
        ? (result.data as { id?: string }).id
        : undefined);

    router.push(savedId ? governanceHref(savedId) : governanceHref());
    router.refresh();
  });

  const applyTemplate = (templateId: string) => {
    const template = templates.find((item) => item.id === templateId);
    if (!template) return;
    form.setValue("policyYaml", template.policyYaml, { shouldValidate: true });
    if (!form.getValues("name")) {
      form.setValue("name", template.name.slice(0, 100), {
        shouldValidate: true,
      });
    }
    if (!form.getValues("description")) {
      form.setValue("description", template.description);
    }
  };

  const applyBuilder = () => {
    const name = form.getValues("name") || "generated-policy";
    const yaml = buildCustodianPolicyYaml({
      name: name.toLowerCase().replace(/\s+/g, "-").slice(0, 64),
      resource: builderResource,
      filterIds: builderFilters,
      description: form.getValues("description") || undefined,
    });
    form.setValue("policyYaml", yaml, { shouldValidate: true });
  };

  const installPack = async (packId: string) => {
    if (!providerId) return;
    setPackMessage(null);
    setSaving(true);
    const result = await installCustodianPack({ packId, providerId });
    setSaving(false);
    if (result && "error" in result && result.error) {
      setError(
        typeof result.error === "string"
          ? result.error
          : "Failed to install pack.",
      );
      return;
    }
    setPackMessage("Pack installed. Policies appear on the policy list.");
    router.refresh();
  };

  return (
    <form className="flex max-w-3xl flex-col gap-4" onSubmit={onSubmit}>
      <div className="flex flex-col gap-2">
        <Label htmlFor="custodian-name">Name</Label>
        <Input id="custodian-name" {...form.register("name")} />
        {form.formState.errors.name ? (
          <p className="text-text-error text-sm">
            {form.formState.errors.name.message}
          </p>
        ) : null}
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="custodian-description">Description</Label>
        <Input id="custodian-description" {...form.register("description")} />
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="custodian-provider">Cloud provider</Label>
        <select
          id="custodian-provider"
          className="border-border-neutral-secondary bg-bg-neutral-primary text-text-neutral-primary rounded-md border px-3 py-2 text-sm"
          {...form.register("providerId")}
        >
          {providers.length === 0 ? (
            <option value="">No supported providers connected</option>
          ) : (
            providers.map((provider) => (
              <option key={provider.id} value={provider.id}>
                {provider.label}
              </option>
            ))
          )}
        </select>
        {form.formState.errors.providerId ? (
          <p className="text-text-error text-sm">
            {form.formState.errors.providerId.message}
          </p>
        ) : null}
      </div>

      {!policyId && templates.length > 0 ? (
        <fieldset className="border-border-neutral-secondary flex flex-col gap-3 rounded-xl border p-4">
          <legend className="text-text-neutral-primary px-1 text-sm font-semibold">
            Starter templates
          </legend>
          <p className="text-text-neutral-secondary text-xs">
            Load a validated dry-run starter. Actions / remediate are never
            included.
          </p>
          <div className="flex flex-wrap gap-2">
            {templates.map((template) => (
              <Button
                key={template.id}
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => applyTemplate(template.id)}
              >
                {template.name}
              </Button>
            ))}
          </div>
          {packs.map((pack) => (
            <div key={pack.id} className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={saving || !providerId}
                onClick={() => installPack(pack.id)}
              >
                Install {pack.name}
              </Button>
              <span className="text-text-neutral-secondary text-xs">
                {pack.description}
              </span>
            </div>
          ))}
          {packMessage ? (
            <p className="text-text-neutral-secondary text-sm">{packMessage}</p>
          ) : null}
        </fieldset>
      ) : null}

      <fieldset className="border-border-neutral-secondary flex flex-col gap-3 rounded-xl border p-4">
        <legend className="text-text-neutral-primary px-1 text-sm font-semibold">
          Visual builder
        </legend>
        <p className="text-text-neutral-secondary text-xs">
          Pick a resource and filters, then write YAML into the editor. Dry-run
          only — actions stay hidden.
        </p>
        <div className="flex flex-col gap-2">
          <Label htmlFor="custodian-builder-resource">Resource</Label>
          <select
            id="custodian-builder-resource"
            className="border-border-neutral-secondary bg-bg-neutral-primary text-text-neutral-primary rounded-md border px-3 py-2 text-sm"
            value={builderResource}
            onChange={(event) => {
              const next = event.target.value as CustodianBuilderResource;
              setBuilderResource(next);
              const first = filtersForResource(next)[0];
              setBuilderFilters(first ? [first.id] : []);
            }}
          >
            {CUSTODIAN_BUILDER_RESOURCES.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
        </div>
        <div className="flex flex-col gap-2">
          <span className="text-sm font-medium">Filters</span>
          {builderFilterOptions.map((option) => {
            const checked = builderFilters.includes(option.id);
            return (
              <label
                key={option.id}
                className="text-text-neutral-primary flex items-start gap-2 text-sm"
              >
                <input
                  type="checkbox"
                  className="mt-1"
                  checked={checked}
                  onChange={(event) => {
                    if (event.target.checked) {
                      setBuilderFilters([...builderFilters, option.id]);
                    } else {
                      setBuilderFilters(
                        builderFilters.filter((id) => id !== option.id),
                      );
                    }
                  }}
                />
                <span>{option.label}</span>
              </label>
            );
          })}
        </div>
        <Button type="button" variant="ghost" size="sm" onClick={applyBuilder}>
          Write YAML from builder
        </Button>
      </fieldset>

      <div className="flex flex-col gap-2">
        <Label htmlFor="custodian-yaml">Policy YAML</Label>
        <Textarea
          id="custodian-yaml"
          className="min-h-64 font-mono text-sm"
          {...form.register("policyYaml")}
        />
        {form.formState.errors.policyYaml ? (
          <p className="text-text-error text-sm">
            {form.formState.errors.policyYaml.message}
          </p>
        ) : null}
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="custodian-regions">
          Region override (optional, comma-separated)
        </Label>
        <Input
          id="custodian-regions"
          placeholder="us-east-1, eu-west-1"
          className="font-mono text-sm"
          {...form.register("regionsOverride")}
        />
        <p className="text-text-neutral-secondary text-xs">
          Leave blank to use the provider scanner regions.
        </p>
      </div>

      <fieldset className="border-border-neutral-secondary flex flex-col gap-3 rounded-xl border p-4">
        <legend className="text-text-neutral-primary px-1 text-sm font-semibold">
          Dry-run schedule
        </legend>
        <p className="text-text-neutral-secondary text-xs">
          Scheduled runs stay dry-run only. Apply / remediate is never enabled.
        </p>

        <div className="flex flex-col gap-2">
          <Label htmlFor="custodian-schedule-preset">Cadence</Label>
          <select
            id="custodian-schedule-preset"
            className="border-border-neutral-secondary bg-bg-neutral-primary text-text-neutral-primary rounded-md border px-3 py-2 text-sm"
            {...form.register("schedulePreset")}
          >
            <option value={CUSTODIAN_SCHEDULE_PRESET.DISABLED}>Off</option>
            <option value={CUSTODIAN_SCHEDULE_PRESET.HOURLY}>Hourly</option>
            <option value={CUSTODIAN_SCHEDULE_PRESET.DAILY}>Daily</option>
            <option value={CUSTODIAN_SCHEDULE_PRESET.WEEKLY}>Weekly</option>
            <option value={CUSTODIAN_SCHEDULE_PRESET.CUSTOM}>
              Custom cron
            </option>
          </select>
        </div>

        {schedulePreset === CUSTODIAN_SCHEDULE_PRESET.DAILY ||
        schedulePreset === CUSTODIAN_SCHEDULE_PRESET.WEEKLY ? (
          <div className="flex flex-col gap-2">
            <Label htmlFor="custodian-schedule-hour">Hour (0–23)</Label>
            <Input
              id="custodian-schedule-hour"
              type="number"
              min={0}
              max={23}
              {...form.register("scheduleHour")}
            />
          </div>
        ) : null}

        {schedulePreset === CUSTODIAN_SCHEDULE_PRESET.WEEKLY ? (
          <div className="flex flex-col gap-2">
            <Label htmlFor="custodian-schedule-weekday">Day of week</Label>
            <select
              id="custodian-schedule-weekday"
              className="border-border-neutral-secondary bg-bg-neutral-primary text-text-neutral-primary rounded-md border px-3 py-2 text-sm"
              {...form.register("scheduleWeekday")}
            >
              {WEEKDAYS.map((day) => (
                <option key={day.value} value={day.value}>
                  {day.label}
                </option>
              ))}
            </select>
          </div>
        ) : null}

        {schedulePreset === CUSTODIAN_SCHEDULE_PRESET.CUSTOM ? (
          <div className="flex flex-col gap-2">
            <Label htmlFor="custodian-schedule-cron">
              Cron (minute hour day month weekday)
            </Label>
            <Input
              id="custodian-schedule-cron"
              className="font-mono text-sm"
              placeholder="0 9 * * 1-5"
              {...form.register("scheduleCron")}
            />
            {form.formState.errors.scheduleCron ? (
              <p className="text-text-error text-sm">
                {form.formState.errors.scheduleCron.message}
              </p>
            ) : null}
          </div>
        ) : null}

        {schedulePreset !== CUSTODIAN_SCHEDULE_PRESET.DISABLED ? (
          <div className="flex flex-col gap-2">
            <Label htmlFor="custodian-schedule-timezone">Timezone</Label>
            <Input
              id="custodian-schedule-timezone"
              placeholder="UTC"
              {...form.register("scheduleTimezone")}
            />
          </div>
        ) : null}
      </fieldset>

      {error ? <p className="text-text-error text-sm">{error}</p> : null}

      <div className="flex gap-2">
        <Button type="submit" disabled={saving || providers.length === 0}>
          {saving ? "Saving…" : policyId ? "Save changes" : "Create policy"}
        </Button>
        <Button
          type="button"
          variant="ghost"
          onClick={() => router.push(governanceHref())}
        >
          Cancel
        </Button>
      </div>
    </form>
  );
};
