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
  FormActions,
  FormAlert,
  FormChoiceGroup,
  FormField,
} from "@/cloudsneeker/components/form-layout";
import { SectionCard } from "@/cloudsneeker/components/section-card";
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
import {
  CARD_LIST_CLASS,
  FORM_CHECK_CLASS,
  FORM_CHOICE_CLASS,
  FORM_CLASS,
  FORM_SELECT_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import { governanceHref } from "@/cloudsneeker/routes";
import { Button, Input, Textarea } from "@/components/shadcn";

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
  const [builderFilters, setBuilderFilters] = useState<string[]>([
    "unattached",
  ]);
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

  const errors = form.formState.errors;

  return (
    <form className={FORM_CLASS} onSubmit={onSubmit}>
      <SectionCard
        title="Policy"
        description="Name the policy and pick the cloud account it checks."
      >
        <FormField
          id="custodian-name"
          label="Name"
          error={errors.name?.message}
        >
          <Input id="custodian-name" {...form.register("name")} />
        </FormField>

        <FormField
          id="custodian-description"
          label="Description"
          optional
          error={errors.description?.message}
        >
          <Input id="custodian-description" {...form.register("description")} />
        </FormField>

        <FormField
          id="custodian-provider"
          label="Cloud provider"
          error={errors.providerId?.message}
        >
          <select
            id="custodian-provider"
            className={FORM_SELECT_CLASS}
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
        </FormField>
      </SectionCard>

      {!policyId && templates.length > 0 ? (
        <SectionCard
          title="Starter templates"
          description="Load a validated dry-run starter. Actions / remediate are never included."
        >
          <div className="flex flex-wrap gap-2">
            {templates.map((template) => (
              <Button
                key={template.id}
                type="button"
                variant="outline"
                size="sm"
                onClick={() => applyTemplate(template.id)}
              >
                {template.name}
              </Button>
            ))}
          </div>
          {packs.length > 0 ? (
            <ul className={CARD_LIST_CLASS}>
              {packs.map((pack) => (
                <li
                  key={pack.id}
                  className="flex flex-col gap-2 p-3 sm:flex-row sm:items-center sm:justify-between"
                >
                  <span className="text-text-neutral-secondary min-w-0 text-sm">
                    {pack.description}
                  </span>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="w-full sm:w-auto sm:shrink-0"
                    disabled={saving || !providerId}
                    onClick={() => installPack(pack.id)}
                  >
                    Install {pack.name}
                  </Button>
                </li>
              ))}
            </ul>
          ) : null}
          {packMessage ? (
            <p role="status" className="text-text-neutral-secondary text-sm">
              {packMessage}
            </p>
          ) : null}
        </SectionCard>
      ) : null}

      <SectionCard
        title="Visual builder"
        description="Pick a resource and filters, then write YAML into the editor. Dry-run only — actions stay hidden."
      >
        <FormField id="custodian-builder-resource" label="Resource">
          <select
            id="custodian-builder-resource"
            className={FORM_SELECT_CLASS}
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
        </FormField>
        <FormChoiceGroup legend="Filters">
          {builderFilterOptions.map((option) => {
            const checked = builderFilters.includes(option.id);
            return (
              <label key={option.id} className={FORM_CHOICE_CLASS}>
                <input
                  type="checkbox"
                  className={FORM_CHECK_CLASS}
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
                <span className="min-w-0">{option.label}</span>
              </label>
            );
          })}
        </FormChoiceGroup>
        <div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="w-full sm:w-auto"
            onClick={applyBuilder}
          >
            Write YAML from builder
          </Button>
        </div>
      </SectionCard>

      <SectionCard
        title="Policy definition"
        description="The YAML that runs. Regions default to the provider's scan regions."
      >
        <FormField
          id="custodian-yaml"
          label="Policy YAML"
          error={errors.policyYaml?.message}
        >
          <Textarea
            id="custodian-yaml"
            className="min-h-64 font-mono text-sm"
            spellCheck={false}
            {...form.register("policyYaml")}
          />
        </FormField>

        <FormField
          id="custodian-regions"
          label="Region override"
          optional
          help="Comma-separated. Leave blank to use the provider scanner regions."
          error={errors.regionsOverride?.message}
        >
          <Input
            id="custodian-regions"
            placeholder="us-east-1, eu-west-1"
            className="font-mono text-sm"
            {...form.register("regionsOverride")}
          />
        </FormField>
      </SectionCard>

      <SectionCard
        title="Dry-run schedule"
        description="Scheduled runs stay dry-run only. Apply / remediate is never enabled."
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <FormField id="custodian-schedule-preset" label="Cadence">
            <select
              id="custodian-schedule-preset"
              className={FORM_SELECT_CLASS}
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
          </FormField>

          {schedulePreset === CUSTODIAN_SCHEDULE_PRESET.DAILY ||
          schedulePreset === CUSTODIAN_SCHEDULE_PRESET.WEEKLY ? (
            <FormField
              id="custodian-schedule-hour"
              label="Hour (0–23)"
              error={errors.scheduleHour?.message}
            >
              <Input
                id="custodian-schedule-hour"
                type="number"
                min={0}
                max={23}
                {...form.register("scheduleHour")}
              />
            </FormField>
          ) : null}

          {schedulePreset === CUSTODIAN_SCHEDULE_PRESET.WEEKLY ? (
            <FormField id="custodian-schedule-weekday" label="Day of week">
              <select
                id="custodian-schedule-weekday"
                className={FORM_SELECT_CLASS}
                {...form.register("scheduleWeekday")}
              >
                {WEEKDAYS.map((day) => (
                  <option key={day.value} value={day.value}>
                    {day.label}
                  </option>
                ))}
              </select>
            </FormField>
          ) : null}

          {schedulePreset === CUSTODIAN_SCHEDULE_PRESET.CUSTOM ? (
            <FormField
              id="custodian-schedule-cron"
              label="Cron"
              help="Five fields: minute hour day month weekday."
              error={errors.scheduleCron?.message}
            >
              <Input
                id="custodian-schedule-cron"
                className="font-mono text-sm"
                placeholder="0 9 * * 1-5"
                {...form.register("scheduleCron")}
              />
            </FormField>
          ) : null}

          {schedulePreset !== CUSTODIAN_SCHEDULE_PRESET.DISABLED ? (
            <FormField
              id="custodian-schedule-timezone"
              label="Timezone"
              error={errors.scheduleTimezone?.message}
            >
              <Input
                id="custodian-schedule-timezone"
                placeholder="UTC"
                {...form.register("scheduleTimezone")}
              />
            </FormField>
          ) : null}
        </div>
      </SectionCard>

      <FormAlert message={error} />

      <FormActions>
        <Button
          type="button"
          variant="ghost"
          onClick={() => router.push(governanceHref())}
        >
          Cancel
        </Button>
        <Button type="submit" disabled={saving || providers.length === 0}>
          {saving ? "Saving…" : policyId ? "Save changes" : "Create policy"}
        </Button>
      </FormActions>
    </form>
  );
};
