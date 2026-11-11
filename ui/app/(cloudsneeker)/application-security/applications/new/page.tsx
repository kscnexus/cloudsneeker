import { Boxes } from "lucide-react";

import { AppSecApplicationForm } from "@/cloudsneeker/components/appsec-application-form";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import {
  loadProfileOptions,
  loadTargetOptions,
} from "@/cloudsneeker/lib/appsec-server";
import { ContentLayout } from "@/components/shadcn/content-layout";

export default async function NewAppSecurityApplicationPage() {
  const [targets, profiles] = await Promise.all([
    loadTargetOptions(),
    loadProfileOptions(),
  ]);
  return (
    <ContentLayout title="New application" icon={<Boxes />}>
      <PageHeader description="Name the application, describe its risk context and assign the assets that belong to it." />
      <AppSecApplicationForm targets={targets} profiles={profiles} />
    </ContentLayout>
  );
}
