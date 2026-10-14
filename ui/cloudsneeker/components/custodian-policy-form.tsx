"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useForm, useWatch } from "react-hook-form";

import {
  createCustodianPolicy,
  updateCustodianPolicy,
} from "@/cloudsneeker/actions/custodian";
import {
  custodianPolicyFormSchema,
  type CustodianPolicyFormInput,
  type CustodianPolicyFormValues,
} from "@/cloudsneeker/lib/custodian-form-schema";
import { CUSTODIAN_SCHEDULE_PRESET } from "@/cloudsneeker/lib/custodian-schedule";
import { Button, Input, Label, Textarea } from "@/components/shadcn";

interface AwsProviderOption {
  id: string;
  label: string;
}

interface CustodianPolicyFormProps {
  providers: AwsProviderOption[];
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
    },
  });

  const schedulePreset = useWatch({
    control: form.control,
    name: "schedulePreset",
  });

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
    };
    const result = policyId
      ? await updateCustodianPolicy(policyId, payload)
      : await createCustodianPolicy(payload);

    setSaving(false);

    if (result && "error" in result && result.error) {
      setError(
        typeof result.error === "string"
          ? result.error
          : "Failed to save Custodian policy.",
      );
      return;
    }

    const savedId =
      policyId ??
      (result && "data" in result && result.data && !Array.isArray(result.data)
        ? (result.data as { id?: string }).id
        : undefined);

    router.push(savedId ? `/custodian/${savedId}` : "/custodian");
    router.refresh();
  });

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
          onClick={() => router.push("/custodian")}
        >
          Cancel
        </Button>
      </div>
    </form>
  );
};
