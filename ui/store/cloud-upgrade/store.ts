import { create } from "zustand";

import { BRAND } from "@/cloudsneeker/brand"; // cloudsneeker-hook
import {
  CLOUD_UPGRADE_FEATURE,
  type UpgradeFeature,
} from "@/types/cloud-upgrade";

interface CloudUpgradeStoreState {
  activeFeature: UpgradeFeature | null;
  retainedFeature: UpgradeFeature;
  returnFocusElement: HTMLElement | null;
  openCloudUpgrade: (
    feature: UpgradeFeature,
    returnFocusElement?: HTMLElement,
  ) => void;
  closeCloudUpgrade: () => void;
}

// Upgrade prompts are ephemeral and shared so only one modal can be open.
export const useCloudUpgradeStore = create<CloudUpgradeStoreState>((set) => ({
  activeFeature: null,
  retainedFeature: CLOUD_UPGRADE_FEATURE.GENERAL,
  returnFocusElement: null,
  openCloudUpgrade: (activeFeature, requestedReturnFocusElement) =>
    BRAND.showUpsell && // cloudsneeker-hook: single edition, no upsell modal
    set({
      activeFeature,
      retainedFeature: activeFeature,
      returnFocusElement:
        requestedReturnFocusElement ??
        (document.activeElement instanceof HTMLElement
          ? document.activeElement
          : null),
    }),
  closeCloudUpgrade: () => set({ activeFeature: null }),
}));
