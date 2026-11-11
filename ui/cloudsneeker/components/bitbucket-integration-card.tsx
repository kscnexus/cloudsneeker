"use client";

import { FolderGit2, SettingsIcon } from "lucide-react";
import Link from "next/link";

import { BITBUCKET_IMPORT_ROUTE } from "@/cloudsneeker/routes";
import { Button, Card, CardContent, CardHeader } from "@/components/shadcn";

export const BitbucketIntegrationCard = () => {
  return (
    <Card variant="base" padding="lg">
      <CardHeader>
        <div className="flex w-full flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <FolderGit2 className="text-text-neutral-secondary size-10" />
            <div className="flex flex-col gap-1">
              <h4 className="text-text-neutral-primary text-lg font-bold">
                Bitbucket
              </h4>
              <p className="text-text-neutral-tertiary text-xs text-nowrap">
                Add every repository in a workspace for code scanning.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 self-end sm:self-center">
            <Button asChild size="sm">
              <Link href={BITBUCKET_IMPORT_ROUTE}>
                <SettingsIcon size={14} />
                Import repositories
              </Link>
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-text-neutral-secondary text-sm">
          Connect a Bitbucket Cloud workspace or a Bitbucket Data Center project
          with one read-only token, pick the repositories, and they are added as
          Infrastructure as Code providers.
        </p>
      </CardContent>
    </Card>
  );
};
