"use client";

import { FolderGit2, SettingsIcon } from "lucide-react";
import Link from "next/link";

import { GITHUB_REPOSITORIES_ROUTE } from "@/cloudsneeker/routes";
import { Button, Card, CardContent, CardHeader } from "@/components/shadcn";

export const GithubIntegrationCard = () => {
  return (
    <Card variant="base" padding="lg">
      <CardHeader>
        <div className="flex w-full flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <FolderGit2 className="text-text-neutral-secondary size-10" />
            <div className="flex flex-col gap-1">
              <h4 className="text-text-neutral-primary text-lg font-bold">
                GitHub repositories
              </h4>
              <p className="text-text-neutral-tertiary text-xs text-nowrap">
                Scan code with your GitHub connection.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 self-end sm:self-center">
            <Button asChild size="sm">
              <Link href={GITHUB_REPOSITORIES_ROUTE}>
                <SettingsIcon size={14} />
                Pick repositories
              </Link>
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-text-neutral-secondary text-sm">
          List the repositories your GitHub App or token can read and add the
          ones you pick as Infrastructure as Code providers. They need no token
          of their own: code scans use the GitHub connection.
        </p>
      </CardContent>
    </Card>
  );
};
