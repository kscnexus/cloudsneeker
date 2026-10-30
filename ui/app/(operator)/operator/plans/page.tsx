import { getOperatorMe, listPlans } from "@/cloudsneeker/actions/operator";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { OperatorLoadError } from "@/cloudsneeker/components/operator-shell";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { PlanEditor } from "@/cloudsneeker/components/plan-editor";
import {
  isListResponse,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
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

export default async function OperatorPlansPage() {
  const [plansResponse, meResponse] = await Promise.all([
    listPlans(),
    getOperatorMe(),
  ]);
  const me =
    responseResource<{ attributes: OperatorMeAttributes }>(meResponse)
      ?.attributes ?? null;
  const canEdit = operatorCan(me, OPERATOR_CAPABILITY.MANAGE_PLANS);

  return (
    <>
      <PageHeader
        title="Plans"
        description="The plan catalogue. A change applies to every customer on the plan within a minute. Per-customer toggles and overrides live on the customer page."
      />
      {!isListResponse(plansResponse) ? (
        <OperatorLoadError
          title="Plans unavailable"
          message={responseError(
            plansResponse,
            "The plan catalogue could not be loaded.",
          )}
          retryHref={OPERATOR_ROUTE.PLANS}
        />
      ) : (
        <PlanList
          plans={responseList<PlanResource>(plansResponse)}
          canEdit={canEdit}
        />
      )}
    </>
  );
}

const PlanList = ({
  plans,
  canEdit,
}: {
  plans: PlanResource[];
  canEdit: boolean;
}) => (
  <div className="flex flex-col gap-6">
    {plans.length === 0 ? (
      <EmptyState title="No plans" description="Create the first plan below." />
    ) : (
      plans.map((plan) => (
        <PlanEditor key={plan.id} plan={plan.attributes} canEdit={canEdit} />
      ))
    )}
    {canEdit ? <PlanEditor canEdit /> : null}
  </div>
);
