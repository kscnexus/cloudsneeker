"use client";

import { useEffect } from "react";

import { usePlanStore } from "@/cloudsneeker/lib/plan-store";

interface PlanStateInitializerProps {
  /** Plan features; `null` when the entitlements could not be loaded. */
  features: string[] | null;
  isOperator: boolean;
}

/** Hands the server-loaded plan to the sidebar after hydration. */
export const PlanStateInitializer = ({
  features,
  isOperator,
}: PlanStateInitializerProps) => {
  const setPlanState = usePlanStore((state) => state.setPlanState);

  useEffect(() => {
    setPlanState(features, isOperator);
  }, [features, isOperator, setPlanState]);

  return null;
};
