import { getEntitlements } from "@/cloudsneeker/actions/entitlements";
import { PlanSummary } from "@/cloudsneeker/components/plan-summary";
import { responseResource } from "@/cloudsneeker/lib/operator";
import type { EntitlementsResource } from "@/cloudsneeker/types/operator";

/** Plan name and end date on the profile page (one `cloudsneeker-hook`). */
export const PlanSummaryCard = async () => {
  const response = await getEntitlements().catch(() => null);
  const entitlements = responseResource<EntitlementsResource>(response);
  if (!entitlements) return null;
  return <PlanSummary entitlements={entitlements.attributes} />;
};
