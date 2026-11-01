"use client";

import Link from "next/link";
import { type FormEvent, useState } from "react";

import { createCustomer } from "@/cloudsneeker/actions/operator";
import { AdminInvitationLink } from "@/cloudsneeker/components/admin-invitation-link";
import {
  FormActions,
  FormAlert,
  FormField,
} from "@/cloudsneeker/components/form-layout";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { SUBSCRIPTION_STATUS_LABEL } from "@/cloudsneeker/lib/entitlements";
import {
  CUSTOMER_NAME_MAX,
  type CustomerFormValues,
  customerPayload,
  emptyCustomerForm,
  INITIAL_STATUSES,
  type InitialStatus,
  invitationFromMeta,
  isErrorResult,
  responseError,
  responseResource,
} from "@/cloudsneeker/lib/operator";
import { FORM_CLASS, FORM_SELECT_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { OPERATOR_ROUTE, operatorCustomerHref } from "@/cloudsneeker/routes";
import {
  type PlanRef,
  SUBSCRIPTION_STATUS,
  type TenantInvitation,
} from "@/cloudsneeker/types/operator";
import { Button, Input, Textarea } from "@/components/shadcn";

interface CreatedCustomer {
  tenantId: string;
  name: string;
  invitation: TenantInvitation;
}

interface CustomerCreateFormProps {
  plans: PlanRef[];
  defaultPlan: string;
}

export const CustomerCreateForm = ({
  plans,
  defaultPlan,
}: CustomerCreateFormProps) => {
  const [values, setValues] = useState<CustomerFormValues>(() =>
    emptyCustomerForm(defaultPlan),
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<CreatedCustomer | null>(null);

  const set = <K extends keyof CustomerFormValues>(
    key: K,
    value: CustomerFormValues[K],
  ) => setValues((current) => ({ ...current, [key]: value }));

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const { payload, error: invalid } = customerPayload(values);
    if (!payload) {
      setError(invalid);
      return;
    }
    setSaving(true);
    setError(null);
    const result = await createCustomer(payload);
    setSaving(false);
    const tenant = responseResource<{ id: string }>(result);
    const invitation = invitationFromMeta(result);
    if (isErrorResult(result) || !tenant || !invitation) {
      setError(responseError(result, "The customer could not be created."));
      return;
    }
    setCreated({ tenantId: tenant.id, name: payload.name, invitation });
  };

  if (created) {
    return (
      <SectionCard
        title={`${created.name} is ready`}
        description="The organization, its admin role and its subscription exist. Nobody is a member until the administrator accepts."
      >
        <AdminInvitationLink invitation={created.invitation} />
        <FormActions>
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              setCreated(null);
              setValues(emptyCustomerForm(defaultPlan));
            }}
          >
            Create another
          </Button>
          <Button asChild>
            <Link href={operatorCustomerHref(created.tenantId)}>
              Open customer
            </Link>
          </Button>
        </FormActions>
      </SectionCard>
    );
  }

  const isTrial = values.status === SUBSCRIPTION_STATUS.TRIAL;

  return (
    <form onSubmit={onSubmit} className={FORM_CLASS} aria-label="New customer">
      <SectionCard
        title="Organization"
        description="The customer's administrator gets an invitation link and becomes the owner when they accept. You do not join the organization."
      >
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField id="customer-name" label="Organization name">
            <Input
              id="customer-name"
              value={values.name}
              maxLength={CUSTOMER_NAME_MAX}
              autoComplete="organization"
              onChange={(event) => set("name", event.target.value)}
              required
            />
          </FormField>
          <FormField
            id="customer-admin-email"
            label="Administrator email"
            help="They set their own password when they accept."
          >
            <Input
              id="customer-admin-email"
              type="email"
              value={values.adminEmail}
              autoComplete="off"
              onChange={(event) => set("adminEmail", event.target.value)}
              required
            />
          </FormField>
        </div>
      </SectionCard>

      <SectionCard
        title="Subscription"
        description="Change features, limits and seats on the customer page afterwards."
      >
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <FormField id="customer-plan" label="Plan">
            <select
              id="customer-plan"
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
          <FormField id="customer-status" label="Status">
            <select
              id="customer-status"
              value={values.status}
              onChange={(event) =>
                set("status", event.target.value as InitialStatus)
              }
              className={FORM_SELECT_CLASS}
            >
              {INITIAL_STATUSES.map((status) => (
                <option key={status} value={status}>
                  {SUBSCRIPTION_STATUS_LABEL[status]}
                </option>
              ))}
            </select>
          </FormField>
          {isTrial ? (
            <FormField id="customer-trial-ends" label="Trial ends" optional>
              <Input
                id="customer-trial-ends"
                type="date"
                value={values.trialEndsAt}
                onChange={(event) => set("trialEndsAt", event.target.value)}
              />
            </FormField>
          ) : null}
          <FormField
            id="customer-ends"
            label="Ends"
            optional
            help="Leave empty for no end date."
          >
            <Input
              id="customer-ends"
              type="date"
              value={values.endsAt}
              onChange={(event) => set("endsAt", event.target.value)}
            />
          </FormField>
          <FormField
            id="customer-external-id"
            label="External customer ID"
            optional
          >
            <Input
              id="customer-external-id"
              value={values.externalCustomerId}
              maxLength={255}
              onChange={(event) =>
                set("externalCustomerId", event.target.value)
              }
            />
          </FormField>
        </div>
        <FormField id="customer-notes" label="Notes" optional>
          <Textarea
            id="customer-notes"
            value={values.notes}
            onChange={(event) => set("notes", event.target.value)}
          />
        </FormField>
      </SectionCard>

      <FormAlert message={error} />
      <FormActions>
        <Button asChild variant="outline">
          <Link href={OPERATOR_ROUTE.CUSTOMERS}>Cancel</Link>
        </Button>
        <Button type="submit" disabled={saving}>
          {saving ? "Creating…" : "Create customer"}
        </Button>
      </FormActions>
    </form>
  );
};
