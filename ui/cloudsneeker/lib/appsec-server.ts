// Server-side loaders shared by the Application Security pages.

import { auth } from "@/auth.config";
import {
  getAppSecCapabilities,
  listAppSecProfiles,
} from "@/cloudsneeker/actions/appsec";
import type {
  AppSecProfileOption,
  AppSecTargetOption,
} from "@/cloudsneeker/components/appsec-application-form";
import { attributesOf } from "@/cloudsneeker/lib/appsec";
import { responseList } from "@/cloudsneeker/lib/findings-links";
import { loadAllTargets } from "@/cloudsneeker/lib/trivy-targets-data";
import type {
  AppSecCapabilities,
  AppSecProfileAttributes,
  AppSecResource,
} from "@/cloudsneeker/types/appsec";

interface TargetResource {
  id: string;
  attributes: {
    name: string;
    mode: string;
    application_id?: string | null;
    application_name?: string | null;
  };
}

/** True when the signed-in role may change scans, profiles and policies. */
export const canManageScans = async (): Promise<boolean> => {
  const session = await auth();
  return Boolean(session?.user?.permissions?.manage_scans);
};

export const loadTargetOptions = async (): Promise<AppSecTargetOption[]> => {
  const loaded = await loadAllTargets({}, "name");
  const targets = (loaded?.targets ?? []) as unknown as TargetResource[];
  return targets.map((target) => ({
    id: target.id,
    name: target.attributes.name,
    mode: target.attributes.mode,
    applicationId: target.attributes.application_id ?? null,
    applicationName: target.attributes.application_name ?? null,
  }));
};

export const loadProfiles = async (): Promise<
  AppSecResource<AppSecProfileAttributes>[]
> =>
  responseList<AppSecResource<AppSecProfileAttributes>>(
    await listAppSecProfiles(),
  );

/** Enabled profiles as select options. */
export const loadProfileOptions = async (): Promise<AppSecProfileOption[]> =>
  (await loadProfiles())
    .filter((profile) => profile.attributes.enabled)
    .map((profile) => ({
      ref: profile.attributes.ref,
      name: profile.attributes.builtin
        ? `${profile.attributes.name} (built-in)`
        : profile.attributes.name,
    }));

export const loadCapabilities = async (): Promise<AppSecCapabilities | null> =>
  attributesOf<AppSecCapabilities>(await getAppSecCapabilities());
