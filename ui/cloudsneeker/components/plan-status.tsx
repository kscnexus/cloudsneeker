import { getEntitlements } from "@/cloudsneeker/actions/entitlements";
import { getOperatorMe } from "@/cloudsneeker/actions/operator";
import { PlanStateInitializer } from "@/cloudsneeker/components/plan-state-initializer";
import { SubscriptionBanner } from "@/cloudsneeker/components/subscription-banner";
import { subscriptionBanner } from "@/cloudsneeker/lib/entitlements";
import { responseResource } from "@/cloudsneeker/lib/operator";
import type { EntitlementsResource } from "@/cloudsneeker/types/operator";

/**
 * Loads the organization's plan once per layout render: feeds the sidebar
 * (features, operator link) and shows the subscription banner. Mounted in the
 * signed-in layout through one `cloudsneeker-hook` line. A failed load hides
 * nothing (fail open) and shows no banner.
 */
export const CloudsneekerPlanStatus = async () => {
  const [entitlementsResponse, operatorResponse] = await Promise.all([
    getEntitlements().catch(() => null),
    getOperatorMe().catch(() => null),
  ]);
  const entitlements =
    responseResource<EntitlementsResource>(entitlementsResponse);
  const isOperator = responseResource(operatorResponse) !== null;
  const banner = entitlements
    ? subscriptionBanner(entitlements.attributes)
    : null;

  return (
    <>
      <PlanStateInitializer
        features={entitlements ? entitlements.attributes.features : null}
        isOperator={isOperator}
      />
      {banner ? <SubscriptionBanner banner={banner} /> : null}
    </>
  );
};
