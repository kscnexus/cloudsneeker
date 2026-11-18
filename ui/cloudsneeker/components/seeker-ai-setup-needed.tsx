import { Sparkles } from "lucide-react";
import Link from "next/link";

import { BRAND } from "@/cloudsneeker/brand";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { LIGHTHOUSE_ROUTE } from "@/lib/lighthouse-routes";

import { EmptyState } from "./empty-state";

/**
 * Shown on the assistant page when no model is connected, instead of a
 * silent redirect to the provider settings. Rendered from the upstream
 * page through one `cloudsneeker-hook`.
 */
export const SeekerAiSetupNeeded = () => (
  <ContentLayout title={BRAND.assistantName} icon={<Sparkles />}>
    <EmptyState
      icon={<Sparkles />}
      title={`Connect a model to use ${BRAND.assistantName}`}
      description={`${BRAND.assistantName} answers questions about your findings, scans and compliance. It runs on a language model you connect: OpenAI, Amazon Bedrock or any OpenAI-compatible endpoint.`}
      action={
        <Button asChild size="sm">
          <Link href={LIGHTHOUSE_ROUTE.SETTINGS}>Connect a model</Link>
        </Button>
      }
    />
  </ContentLayout>
);
