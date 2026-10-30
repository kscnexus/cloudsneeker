"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";

import {
  createPlan,
  deletePlan,
  updatePlan,
} from "@/cloudsneeker/actions/operator";
import {
  FormActions,
  FormAlert,
  FormChoiceGroup,
  FormField,
} from "@/cloudsneeker/components/form-layout";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  PLAN_FEATURE_LABEL,
  PLAN_FEATURES,
  PLAN_LIMIT_LABEL,
  PLAN_LIMITS,
} from "@/cloudsneeker/lib/entitlements";
import {
  isErrorResult,
  type PlanFormValues,
  planPayload,
  responseError,
} from "@/cloudsneeker/lib/operator";
import {
  FORM_CHECK_CLASS,
  FORM_CHOICE_CLASS,
  FORM_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import type {
  PlanAttributes,
  PlanFeature,
} from "@/cloudsneeker/types/operator";
import { Button, Input, Textarea } from "@/components/shadcn";

export const planFormValues = (plan?: PlanAttributes): PlanFormValues => {
  const limits: Record<string, string> = {};
  for (const key of PLAN_LIMITS) {
    const value = plan?.limits[key];
    limits[key] = typeof value === "number" ? String(value) : "";
  }
  return {
    code: plan?.code ?? "",
    name: plan?.name ?? "",
    description: plan?.description ?? "",
    features: plan ? [...plan.features] : [],
    limits,
    isPublic: plan?.is_public ?? true,
    sortOrder: String(plan?.sort_order ?? 100),
  };
};

interface PlanEditorProps {
  /** Omitted for the "new plan" form. */
  plan?: PlanAttributes;
  canEdit: boolean;
}

export const PlanEditor = ({ plan, canEdit }: PlanEditorProps) => {
  const router = useRouter();
  const isNew = !plan;
  const [values, setValues] = useState<PlanFormValues>(() =>
    planFormValues(plan),
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const idPrefix = `plan-${plan?.code ?? "new"}`;
  const protectedPlan = plan?.code === "legacy";

  const toggleFeature = (feature: PlanFeature, enabled: boolean) =>
    setValues((current) => ({
      ...current,
      features: enabled
        ? [...current.features.filter((item) => item !== feature), feature]
        : current.features.filter((item) => item !== feature),
    }));

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const { payload, error: invalid } = planPayload(values, {
      includeCode: isNew,
    });
    if (!payload) {
      setError(invalid);
      return;
    }
    setSaving(true);
    setError(null);
    const result = plan
      ? await updatePlan(plan.code, payload)
      : await createPlan(payload);
    setSaving(false);
    if (isErrorResult(result)) {
      setError(responseError(result, "The plan could not be saved."));
      return;
    }
    if (isNew) setValues(planFormValues());
    router.refresh();
  };

  const onDelete = async () => {
    if (!plan) return;
    setSaving(true);
    const result = await deletePlan(plan.code);
    setSaving(false);
    if (isErrorResult(result)) {
      setError(responseError(result, "The plan could not be deleted."));
      return;
    }
    router.refresh();
  };

  return (
    <form
      onSubmit={onSubmit}
      className={FORM_CLASS}
      aria-label={plan?.name ?? "New plan"}
    >
      <SectionCard
        title={plan ? plan.name : "New plan"}
        description={
          plan
            ? `Code ${plan.code} · ${plan.subscriber_count ?? 0} customer(s)${plan.is_public ? "" : " · not public"}`
            : "Add a plan to the catalogue."
        }
      >
        <fieldset disabled={!canEdit || saving} className="flex flex-col gap-4">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            {isNew ? (
              <FormField
                id={`${idPrefix}-code`}
                label="Code"
                help="Lowercase, cannot change later."
              >
                <Input
                  id={`${idPrefix}-code`}
                  value={values.code}
                  onChange={(event) =>
                    setValues({ ...values, code: event.target.value })
                  }
                />
              </FormField>
            ) : null}
            <FormField id={`${idPrefix}-name`} label="Name">
              <Input
                id={`${idPrefix}-name`}
                value={values.name}
                onChange={(event) =>
                  setValues({ ...values, name: event.target.value })
                }
              />
            </FormField>
            <FormField id={`${idPrefix}-sort`} label="Sort order">
              <Input
                id={`${idPrefix}-sort`}
                inputMode="numeric"
                value={values.sortOrder}
                onChange={(event) =>
                  setValues({ ...values, sortOrder: event.target.value })
                }
              />
            </FormField>
          </div>
          <FormField
            id={`${idPrefix}-description`}
            label="Description"
            optional
          >
            <Textarea
              id={`${idPrefix}-description`}
              value={values.description}
              onChange={(event) =>
                setValues({ ...values, description: event.target.value })
              }
            />
          </FormField>
          <label className={FORM_CHOICE_CLASS}>
            <input
              type="checkbox"
              className={FORM_CHECK_CLASS}
              checked={values.isPublic}
              onChange={(event) =>
                setValues({ ...values, isPublic: event.target.checked })
              }
            />
            Public (offered to new customers)
          </label>
          <FormChoiceGroup legend="Features">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {PLAN_FEATURES.map((feature) => (
                <label key={feature} className={FORM_CHOICE_CLASS}>
                  <input
                    type="checkbox"
                    className={FORM_CHECK_CLASS}
                    checked={values.features.includes(feature)}
                    onChange={(event) =>
                      toggleFeature(feature, event.target.checked)
                    }
                  />
                  {PLAN_FEATURE_LABEL[feature]}
                </label>
              ))}
            </div>
          </FormChoiceGroup>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {PLAN_LIMITS.map((key) => (
              <FormField
                key={key}
                id={`${idPrefix}-limit-${key}`}
                label={PLAN_LIMIT_LABEL[key]}
                help="Empty = unlimited"
              >
                <Input
                  id={`${idPrefix}-limit-${key}`}
                  inputMode="numeric"
                  value={values.limits[key] ?? ""}
                  placeholder="Unlimited"
                  onChange={(event) =>
                    setValues({
                      ...values,
                      limits: { ...values.limits, [key]: event.target.value },
                    })
                  }
                />
              </FormField>
            ))}
          </div>
        </fieldset>
        <FormAlert message={error} />
        {canEdit ? (
          <FormActions>
            {plan && !protectedPlan && (plan.subscriber_count ?? 0) === 0 ? (
              <Button
                type="button"
                variant="outline"
                onClick={onDelete}
                disabled={saving}
              >
                Delete plan
              </Button>
            ) : null}
            <Button type="submit" disabled={saving}>
              {saving ? "Saving..." : isNew ? "Create plan" : "Save plan"}
            </Button>
          </FormActions>
        ) : null}
      </SectionCard>
    </form>
  );
};
