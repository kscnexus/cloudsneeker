// Client-only state for the current organization's plan: the features that
// drive the sidebar and whether the signed-in user is a platform operator.
// Filled by `PlanStateInitializer` after hydration; never set on the server,
// so one request's plan cannot leak into another's render. Until it is set
// (`features === null`) the sidebar shows everything.

import { create } from "zustand";

interface PlanStoreState {
  features: string[] | null;
  isOperator: boolean;
  setPlanState: (features: string[] | null, isOperator: boolean) => void;
}

export const usePlanStore = create<PlanStoreState>()((set) => ({
  features: null,
  isOperator: false,
  setPlanState: (features, isOperator) => set({ features, isOperator }),
}));

/**
 * The plan for the sidebar. The sidebar passes it to `withCloudsneekerPlan`
 * (one `cloudsneeker-hook`), so a plan change re-renders and recomputes the
 * navigation.
 */
export const useCloudsneekerPlan = () => {
  const features = usePlanStore((state) => state.features);
  const isOperator = usePlanStore((state) => state.isOperator);
  return { features, isOperator };
};
