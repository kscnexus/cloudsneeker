"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useForm } from "react-hook-form";

import {
  createCustodianPolicy,
  updateCustodianPolicy,
} from "@/cloudsneeker/actions/custodian";
import {
  custodianPolicyFormSchema,
  type CustodianPolicyFormValues,
} from "@/cloudsneeker/lib/custodian-form-schema";
import { Button, Input, Label, Textarea } from "@/components/shadcn";

interface AwsProviderOption {
  id: string;
  label: string;
}

interface CustodianPolicyFormProps {
  providers: AwsProviderOption[];
  initialValues?: CustodianPolicyFormValues;
  policyId?: string;
}

export const CustodianPolicyForm = ({
  providers,
  initialValues,
  policyId,
}: CustodianPolicyFormProps) => {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const form = useForm<CustodianPolicyFormValues>({
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
    },
  });

  const onSubmit = form.handleSubmit(async (values) => {
    setSaving(true);
    setError(null);
    const payload = {
      name: values.name,
      description: values.description ?? "",
      policyYaml: values.policyYaml,
      providerId: values.providerId,
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
        <Label htmlFor="custodian-provider">AWS provider</Label>
        <select
          id="custodian-provider"
          className="border-border-neutral-secondary bg-bg-neutral-primary text-text-neutral-primary rounded-md border px-3 py-2 text-sm"
          {...form.register("providerId")}
        >
          {providers.length === 0 ? (
            <option value="">No AWS providers connected</option>
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
