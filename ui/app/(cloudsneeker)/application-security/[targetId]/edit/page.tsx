import { ScanSearch } from "lucide-react";
import { notFound } from "next/navigation";

import { getProviders } from "@/actions/providers/providers";
import { listAppSecApplications } from "@/cloudsneeker/actions/appsec";
import { getTrivyTarget } from "@/cloudsneeker/actions/trivy";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { TrivyTargetForm } from "@/cloudsneeker/components/trivy-target-form";
import { loadProfileOptions } from "@/cloudsneeker/lib/appsec-server";
import { responseList } from "@/cloudsneeker/lib/findings-links";
import {
  SAST_SOURCE,
  type TrivyTargetFormInput,
} from "@/cloudsneeker/lib/trivy-form-schema";
import {
  labelForProviderType,
  scannersForModeFrom,
} from "@/cloudsneeker/lib/trivy-modes";
import type {
  AppSecApplicationAttributes,
  AppSecResource,
} from "@/cloudsneeker/types/appsec";
import {
  SAST_RULESET,
  type SastRuleset,
  TRIVY_MODE,
  type TrivyTargetResource,
} from "@/cloudsneeker/types/trivy";
import { ContentLayout } from "@/components/shadcn/content-layout";

const SAST_RULESET_VALUES: readonly string[] = Object.values(SAST_RULESET);

const isSastRuleset = (value: string): value is SastRuleset =>
  SAST_RULESET_VALUES.includes(value);

interface EditTrivyTargetPageProps {
  params: Promise<{ targetId: string }>;
}

export default async function EditTrivyTargetPage({
  params,
}: EditTrivyTargetPageProps) {
  const { targetId } = await params;
  const targetResponse = await getTrivyTarget(targetId);

  if (
    !targetResponse ||
    ("error" in targetResponse && targetResponse.error) ||
    !targetResponse.data ||
    Array.isArray(targetResponse.data)
  ) {
    notFound();
  }

  const target = targetResponse.data as TrivyTargetResource;
  const config = target.attributes.config ?? {};
  const [providersResponse, profiles, applicationsResponse] = await Promise.all(
    [
      getProviders({ pageSize: 100 }),
      loadProfileOptions(),
      listAppSecApplications({ "page[size]": "100" }),
    ],
  );
  const applications = responseList<
    AppSecResource<AppSecApplicationAttributes>
  >(applicationsResponse).map((application) => ({
    value: application.id,
    label: application.attributes.name,
  }));
  const providers = (providersResponse?.data ?? []).map((provider) => ({
    id: provider.id,
    providerType: provider.attributes.provider,
    label: [
      labelForProviderType(provider.attributes.provider),
      provider.attributes.alias || provider.attributes.uid || provider.id,
    ]
      .filter(Boolean)
      .join(" · "),
  }));

  const initialValues: TrivyTargetFormInput = {
    name: target.attributes.name,
    description: target.attributes.description ?? "",
    mode: target.attributes.mode,
    providerId: target.attributes.provider_id,
    // Drops scanners saved before each mode had its own list.
    scanners: scannersForModeFrom(
      target.attributes.mode,
      Array.isArray(config.scanners) ? config.scanners : [],
    ),
    images: Array.isArray(config.images) ? config.images.join("\n") : "",
    repositoryUrl:
      typeof config.repository_url === "string" ? config.repository_url : "",
    archiveB64: "",
    sbom: typeof config.sbom === "string" ? config.sbom : "",
    namespace: typeof config.namespace === "string" ? config.namespace : "",
    profile: typeof config.profile === "string" ? config.profile : "",
    applicationId: target.attributes.application_id ?? "",
    // The API never returns uploaded archives; a repository URL means the
    // target reads from Git, otherwise it was created from an archive.
    sastSource:
      typeof config.repository_url === "string" && config.repository_url
        ? SAST_SOURCE.REPOSITORY
        : target.attributes.mode === TRIVY_MODE.SAST
          ? SAST_SOURCE.ARCHIVE
          : SAST_SOURCE.REPOSITORY,
    rulesets: Array.isArray(config.rulesets)
      ? config.rulesets.filter(isSastRuleset)
      : [SAST_RULESET.AUTO],
    exclude: Array.isArray(config.exclude) ? config.exclude.join("\n") : "",
    scheduleEnabled: Boolean(target.attributes.schedule_enabled),
    scheduleCron: target.attributes.schedule_cron ?? "",
    scheduleTimezone: target.attributes.schedule_timezone ?? "UTC",
  };

  return (
    <ContentLayout
      title={`Edit ${target.attributes.name}`}
      icon={<ScanSearch />}
    >
      <PageHeader description="Changes apply from the next scan. Earlier scan results stay as they were." />
      <TrivyTargetForm
        providers={providers}
        profiles={profiles.map((item) => ({
          value: item.ref,
          label: item.name,
        }))}
        applications={applications}
        preservedConfig={
          config.options ? { options: config.options } : undefined
        }
        initialValues={initialValues}
        targetId={targetId}
      />
    </ContentLayout>
  );
}
