"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";

import { updateSubscription } from "@/cloudsneeker/actions/operator";
import {
  FormActions,
  FormAlert,
  FormField,
} from "@/cloudsneeker/components/form-layout";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  PLAN_FEATURE_LABEL,
  PLAN_FEATURES,
  PLAN_LIMIT_LABEL,
  PLAN_LIMITS,
  SUBSCRIPTION_STATUS_LABEL,
} from "@/cloudsneeker/lib/entitlements";
import {
  BILLING_SOURCE_LABEL,
  FEATURE_OVERRIDE,
  type FeatureOverride,
  isErrorResult,
  responseError,
  type SubscriptionFormValues,
  subscriptionFormValues,
  subscriptionPayload,
  UNLIMITED,
} from "@/cloudsneeker/lib/operator";
import { FORM_CLASS, FORM_SELECT_CLASS } from "@/cloudsneeker/lib/ui-classes";
import type {
  BillingSource,
  PlanFeature,
  PlanRef,
  SubscriptionAttributes,
  SubscriptionStatus,
} from "@/cloudsneeker/types/operator";
import { Button, Input, Textarea } from "@/components/shadcn";

const OWNER_ONLY_STATUSES: readonly SubscriptionStatus[] = [
  "suspended",
  "cancelled",
];

const FEATURE_OVERRIDE_LABEL: Record<FeatureOverride, string> = {
  plan: "Plan default",
  on: "Always on",
  off: "Always off",
};

interface SubscriptionEditorProps {
  tenantId: string;
  subscription: SubscriptionAttributes;
  plans: PlanRef[];
  /** Owners may suspend and cancel; billing operators may not. */
  canSuspend: boolean;
}

export const SubscriptionEditor = ({
  tenantId,
  subscription,
  plans,
  canSuspend,
}: SubscriptionEditorProps) => {
  const router = useRouter();
  const [values, setValues] = useState<SubscriptionFormValues>(() =>
    subscriptionFormValues(subscription),
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const set = <K extends keyof SubscriptionFormValues>(
    key: K,
    value: SubscriptionFormValues[K],
  ) => {
    setSaved(false);
    setValues((current) => ({ ...current, [key]: value }));
  };

  const setFeature = (feature: PlanFeature, value: FeatureOverride) =>
    set("featureOverrides", { ...values.featureOverrides, [feature]: value });

  const setLimit = (key: string, value: string) =>
    set("limitOverrides", { ...values.limitOverrides, [key]: value });

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const { payload, error: invalid } = subscriptionPayload(values);
    if (!payload) {
      setError(invalid);
      return;
    }
    setSaving(true);
    setError(null);
    const result = await updateSubscription(tenantId, payload);
    setSaving(false);
    if (isErrorResult(result)) {
      setError(responseError(result, "The subscription could not be saved."));
      return;
    }
    setSaved(true);
    router.refresh();
  };

  const statusOptions = Object.entries(SUBSCRIPTION_STATUS_LABEL).filter(
    ([value]) =>
      canSuspend ||
      value === subscription.status ||
      !OWNER_ONLY_STATUSES.includes(value as SubscriptionStatus),
  );

  return (
    <form onSubmit={onSubmit} className={FORM_CLASS} aria-label="Subscription">
      <SectionCard
        title="Subscription"
        description="Plan, status and dates. Suspended, expired and cancelled organizations become read-only."
      >
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField id="subscription-plan" label="Plan">
            <select
              id="subscription-plan"
              value={values.plan}
              onChange={(event) => set("plan", event.target.value)}
              className={FORM_SELECT_CLASS}
            >
              {plans.map((plan) => (
                <option key={plan.code} value={plan.code}>
                  {plan.name}
                </option>
              ))}
            </select>
          </FormField>
          <FormField
            id="subscription-status"
            label="Status"
            help={
              canSuspend ? undefined : "Only an owner can suspend or cancel."
            }
          >
            <select
              id="subscription-status"
              value={values.status}
              onChange={(event) =>
                set("status", event.target.value as SubscriptionStatus)
              }
              className={FORM_SELECT_CLASS}
            >
              {statusOptions.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </FormField>
          <FormField id="subscription-starts" label="Starts" optional>
            <Input
              id="subscription-starts"
              type="date"
              value={values.startsAt}
              onChange={(event) => set("startsAt", event.target.value)}
            />
          </FormField>
          <FormField
            id="subscription-ends"
            label="Ends"
            optional
            help="Leave empty for no end date. The organization expires on this date."
          >
            <Input
              id="subscription-ends"
              type="date"
              value={values.endsAt}
              onChange={(event) => set("endsAt", event.target.value)}
            />
          </FormField>
          <FormField id="subscription-trial" label="Trial ends" optional>
            <Input
              id="subscription-trial"
              type="date"
              value={values.trialEndsAt}
              onChange={(event) => set("trialEndsAt", event.target.value)}
            />
          </FormField>
          <FormField
            id="subscription-seats"
            label="Seats"
            optional
            help="Replaces the plan's user limit when set."
          >
            <Input
              id="subscription-seats"
              inputMode="numeric"
              value={values.seats}
              onChange={(event) => set("seats", event.target.value)}
            />
          </FormField>
          <FormField id="subscription-billing" label="Billing source">
            <select
              id="subscription-billing"
              value={values.billingSource}
              onChange={(event) =>
                set("billingSource", event.target.value as BillingSource)
              }
              className={FORM_SELECT_CLASS}
            >
              {Object.entries(BILLING_SOURCE_LABEL).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </FormField>
          <FormField
            id="subscription-customer-id"
            label="External customer id"
            optional
          >
            <Input
              id="subscription-customer-id"
              value={values.externalCustomerId}
              onChange={(event) =>
                set("externalCustomerId", event.target.value)
              }
            />
          </FormField>
        </div>
        <FormField
          id="subscription-notes"
          label="Notes"
          optional
          help="Internal only. History records that notes changed, not what they say."
        >
          <Textarea
            id="subscription-notes"
            value={values.notes}
            onChange={(event) => set("notes", event.target.value)}
          />
        </FormField>
      </SectionCard>

      <SectionCard
        title="Feature toggles"
        description="Turn single features on or off for this customer, on top of the plan."
      >
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {PLAN_FEATURES.map((feature) => (
            <FormField
              key={feature}
              id={`feature-${feature}`}
              label={PLAN_FEATURE_LABEL[feature]}
            >
              <select
                id={`feature-${feature}`}
                value={values.featureOverrides[feature]}
                onChange={(event) =>
                  setFeature(feature, event.target.value as FeatureOverride)
                }
                className={FORM_SELECT_CLASS}
              >
                {Object.values(FEATURE_OVERRIDE).map((choice) => (
                  <option key={choice} value={choice}>
                    {FEATURE_OVERRIDE_LABEL[choice]}
                  </option>
                ))}
              </select>
            </FormField>
          ))}
        </div>
      </SectionCard>

      <SectionCard
        title="Limit overrides"
        description={`Leave empty to follow the plan. Enter a number, or "${UNLIMITED}".`}
      >
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {PLAN_LIMITS.map((key) => (
            <FormField
              key={key}
              id={`limit-${key}`}
              label={PLAN_LIMIT_LABEL[key]}
              help={`Effective: ${subscription.limits[key] ?? "unlimited"}`}
            >
              <Input
                id={`limit-${key}`}
                value={values.limitOverrides[key] ?? ""}
                placeholder="Plan default"
                onChange={(event) => setLimit(key, event.target.value)}
              />
            </FormField>
          ))}
        </div>
      </SectionCard>

      <FormAlert message={error} />
      {saved ? (
        <p role="status" className="text-text-success-primary text-sm">
          Saved.
        </p>
      ) : null}
      <FormActions>
        <Button
          type="button"
          variant="outline"
          onClick={() => {
            setValues(subscriptionFormValues(subscription));
            setError(null);
          }}
        >
          Reset
        </Button>
        <Button type="submit" disabled={saving}>
          {saving ? "Saving..." : "Save subscription"}
        </Button>
      </FormActions>
    </form>
  );
};
