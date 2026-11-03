import { Layers, ShieldAlert } from "lucide-react";
import Link from "next/link";

import { getContentVersions } from "@/cloudsneeker/actions/content-versions";
import { ContentVersionsPanel } from "@/cloudsneeker/components/content-versions-panel";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { responseResource } from "@/cloudsneeker/lib/operator";
import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import type { ContentVersionsResource } from "@/cloudsneeker/types/content-versions";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";

export default async function ContentVersionsPage() {
  const resource = responseResource<ContentVersionsResource>(
    await getContentVersions().catch(() => null),
  );

  return (
    <ContentLayout title="Content versions" icon={<Layers />}>
      <PageHeader description="How current detection is: check releases, vulnerability database age, code analysis rules and engine versions." />
      {resource ? (
        <ContentVersionsPanel versions={resource.attributes} />
      ) : (
        <EmptyState
          icon={<ShieldAlert />}
          title="Content versions unavailable"
          description="The versions could not be loaded. Try again in a moment."
          action={
            <Button asChild size="sm" variant="outline">
              <Link href={PRODUCT_ROUTE.CONTENT_VERSIONS}>Retry</Link>
            </Button>
          }
        />
      )}
    </ContentLayout>
  );
}
