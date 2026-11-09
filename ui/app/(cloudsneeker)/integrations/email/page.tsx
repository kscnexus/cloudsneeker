import { redirect } from "next/navigation";

import { getEmailDeliveryConfig } from "@/cloudsneeker/actions/email-delivery";
import { EmailDeliveryForm } from "@/cloudsneeker/components/email-delivery-form";
import { FormAlert } from "@/cloudsneeker/components/form-layout";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { isCloudsneekerFeatureEnabled } from "@/cloudsneeker/features";
import { ContentLayout } from "@/components/shadcn/content-layout";

export default async function EmailDeliveryPage() {
  if (!isCloudsneekerFeatureEnabled("emailDelivery")) {
    redirect("/");
  }

  const config = await getEmailDeliveryConfig();
  const initial = config && !("error" in config) ? config : null;

  return (
    <ContentLayout title="Email">
      <PageHeader description="Configure the SMTP server Cloudsneeker uses to email alert recipients for this tenant." />
      {config && "error" in config ? (
        <FormAlert message={config.error} />
      ) : (
        <EmailDeliveryForm initial={initial} />
      )}
    </ContentLayout>
  );
}
