import { redirect } from "next/navigation";

import { BitbucketImportForm } from "@/cloudsneeker/components/bitbucket-import-form";
import { isCloudsneekerFeatureEnabled } from "@/cloudsneeker/features";
import { ContentLayout } from "@/components/shadcn/content-layout";

export default function BitbucketImportPage() {
  if (!isCloudsneekerFeatureEnabled("bitbucketImport")) {
    redirect("/");
  }

  return (
    <ContentLayout title="Bitbucket">
      <div className="flex flex-col gap-6">
        <p className="text-sm text-gray-600 dark:text-gray-300">
          List the repositories one token can read and add the ones you pick as
          Infrastructure as Code providers. Each provider keeps the token as its
          credentials, so private repositories clone during scans. Use a
          read-only token: Cloudsneeker only clones.
        </p>
        <BitbucketImportForm />
      </div>
    </ContentLayout>
  );
}
