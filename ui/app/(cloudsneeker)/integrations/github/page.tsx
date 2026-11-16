import { redirect } from "next/navigation";

import { getGithubConnections } from "@/cloudsneeker/actions/github-repositories";
import { GithubRepositoriesForm } from "@/cloudsneeker/components/github-repositories-form";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { isCloudsneekerFeatureEnabled } from "@/cloudsneeker/features";
import { ContentLayout } from "@/components/shadcn/content-layout";

export default async function GithubRepositoriesPage() {
  if (!isCloudsneekerFeatureEnabled("githubRepositories")) {
    redirect("/");
  }
  const connections = await getGithubConnections();

  return (
    <ContentLayout title="GitHub repositories">
      <PageHeader description="List the repositories a GitHub connection can read and add the ones you pick as Infrastructure as Code providers for code scanning. They store no token: each scan takes a short-lived, read-only one from the GitHub connection." />
      <GithubRepositoriesForm connections={connections} />
    </ContentLayout>
  );
}
