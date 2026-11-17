import { GitBranch } from "lucide-react";

import { auth } from "@/auth.config";
import { listSourceConnections } from "@/cloudsneeker/actions/appsec";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SourceConnectionsPanel } from "@/cloudsneeker/components/source-connections-panel";
import { responseList } from "@/cloudsneeker/lib/findings-links";
import type {
  AppSecResource,
  SourceConnectionAttributes,
} from "@/cloudsneeker/types/appsec";
import { ContentLayout } from "@/components/shadcn/content-layout";

export default async function AppSecuritySourcesPage() {
  const [response, session] = await Promise.all([
    listSourceConnections(),
    auth(),
  ]);
  const connections = responseList<AppSecResource<SourceConnectionAttributes>>(
    response,
  ).map((item) => ({
    id: item.id,
    label: item.attributes.alias || item.attributes.uid,
    repositoryCount: item.attributes.repository_count,
  }));
  return (
    <ContentLayout title="Code sources" icon={<GitBranch />}>
      <PageHeader description="Import the repositories of a GitHub connection as code sources. They read the connection's credentials, so the token is entered once and a new token reaches every repository." />
      <SourceConnectionsPanel
        connections={connections}
        canManage={Boolean(session?.user?.permissions?.manage_providers)}
      />
    </ContentLayout>
  );
}
