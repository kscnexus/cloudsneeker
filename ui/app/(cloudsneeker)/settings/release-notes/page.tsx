import { NotebookText, ShieldAlert } from "lucide-react";
import Link from "next/link";

import { getContentReleases } from "@/cloudsneeker/actions/content-releases";
import { ContentReleasesPanel } from "@/cloudsneeker/components/content-releases-panel";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import type { ContentReleaseResource } from "@/cloudsneeker/types/content-releases";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";

const releasesFrom = (response: unknown): ContentReleaseResource[] | null => {
  const data = (response as { data?: unknown } | null)?.data;
  return Array.isArray(data) ? (data as ContentReleaseResource[]) : null;
};

export default async function ReleaseNotesPage() {
  const releases = releasesFrom(await getContentReleases().catch(() => null));

  return (
    <ContentLayout title="Release notes" icon={<NotebookText />}>
      <PageHeader
        description={
          <>
            Checks and compliance frameworks added, changed or removed in each
            detection content release.{" "}
            <Link
              className="underline underline-offset-2"
              href={PRODUCT_ROUTE.CONTENT_VERSIONS}
            >
              See the versions running now
            </Link>
            .
          </>
        }
      />
      {releases === null ? (
        <EmptyState
          icon={<ShieldAlert />}
          title="Release notes unavailable"
          description="The release notes could not be loaded. Try again in a moment."
          action={
            <Button asChild size="sm" variant="outline">
              <Link href={PRODUCT_ROUTE.RELEASE_NOTES}>Retry</Link>
            </Button>
          }
        />
      ) : releases.length ? (
        <ContentReleasesPanel
          releases={releases.map((release) => release.attributes)}
        />
      ) : (
        <EmptyState
          icon={<NotebookText />}
          title="No release notes yet"
          description="Release notes appear here after the next detection content update."
        />
      )}
    </ContentLayout>
  );
}
