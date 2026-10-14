import { redirect } from "next/navigation";

import { getEmailDeliveryConfig } from "@/cloudsneeker/actions/email-delivery";
import { EmailDeliveryForm } from "@/cloudsneeker/components/email-delivery-form";
import { isCloudsneekerFeatureEnabled } from "@/cloudsneeker/features";
import { ContentLayout } from "@/components/shadcn/content-layout";

export default async function EmailDeliveryPage() {
  if (!isCloudsneekerFeatureEnabled("emailDelivery")) {
    redirect("/");
  }

  const config = await getEmailDeliveryConfig();
  const initial =
    config && !("error" in config) ? config : null;

  return (
    <ContentLayout title="Email">
      <div className="flex flex-col gap-6">
        <p className="text-sm text-gray-600 dark:text-gray-300">
          Configure the SMTP server Cloudsneeker uses to email alert
          recipients for this tenant.
        </p>
        {config && "error" in config ? (
          <p className="text-sm text-red-600">{config.error}</p>
        ) : (
          <EmailDeliveryForm initial={initial} />
        )}
      </div>
    </ContentLayout>
  );
}
