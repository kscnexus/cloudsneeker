import Link from "next/link";

import { getOperatorMe, listPlans } from "@/cloudsneeker/actions/operator";
import { CustomerCreateForm } from "@/cloudsneeker/components/customer-create-form";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { OperatorLoadError } from "@/cloudsneeker/components/operator-shell";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { responseList } from "@/cloudsneeker/lib/findings-links";
import {
  operatorCan,
  responseError,
  responseResource,
} from "@/cloudsneeker/lib/operator";
import { OPERATOR_ROUTE } from "@/cloudsneeker/routes";
import {
  OPERATOR_CAPABILITY,
  type OperatorMeAttributes,
  type PlanResource,
} from "@/cloudsneeker/types/operator";
import { Button } from "@/components/shadcn";

export default async function OperatorNewCustomerPage() {
  const [meResponse, plansResponse] = await Promise.all([
    getOperatorMe(),
    listPlans(),
  ]);
  const me =
    responseResource<{ attributes: OperatorMeAttributes }>(meResponse)
      ?.attributes ?? null;
  const planResources = responseList<PlanResource>(plansResponse);
  const plans = planResources.map((plan) => ({
    code: plan.attributes.code,
    name: plan.attributes.name,
  }));
  // Plans arrive in catalogue order; start on the first one offered to customers.
  const defaultPlan =
    planResources.find((plan) => plan.attributes.is_public)?.attributes.code ??
    plans[0]?.code ??
    "";
  const canCreate = operatorCan(me, OPERATOR_CAPABILITY.MANAGE_SUBSCRIPTIONS);

  return (
    <>
      <PageHeader
        title="New customer"
        description="Create an organization and invite its administrator."
        actions={
          <Button asChild size="sm" variant="outline">
            <Link href={OPERATOR_ROUTE.CUSTOMERS}>All customers</Link>
          </Button>
        }
      />
      {!canCreate ? (
        <EmptyState
          title="Not available"
          description="Your operator role can view customers but not create them."
        />
      ) : plans.length === 0 ? (
        <OperatorLoadError
          title="Plans unavailable"
          message={responseError(plansResponse, "Plans could not be loaded.")}
          retryHref={OPERATOR_ROUTE.NEW_CUSTOMER}
        />
      ) : (
        <CustomerCreateForm plans={plans} defaultPlan={defaultPlan} />
      )}
    </>
  );
}
