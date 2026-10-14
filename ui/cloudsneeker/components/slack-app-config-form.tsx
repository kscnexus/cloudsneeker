"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  deleteSlackAppConfig,
  saveSlackAppConfig,
  type SlackAppConfigResource,
} from "@/cloudsneeker/actions/slack-app";
import { Button, Input, Label } from "@/components/shadcn";
import { useToast } from "@/components/shadcn/toast/use-toast";

interface SlackAppConfigFormProps {
  initial: SlackAppConfigResource | null;
  redirectUri: string;
}

export const SlackAppConfigForm = ({
  initial,
  redirectUri,
}: SlackAppConfigFormProps) => {
  const { toast } = useToast();
  const router = useRouter();
  const [configId, setConfigId] = useState(initial?.id ?? null);
  const [clientId, setClientId] = useState(initial?.attributes.client_id ?? "");
  const [clientSecret, setClientSecret] = useState("");
  const [hasSecret, setHasSecret] = useState(
    initial?.attributes.has_client_secret ?? false,
  );
  const [isSaving, setIsSaving] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  const onSave = async () => {
    setIsSaving(true);
    try {
      const result = await saveSlackAppConfig(
        {
          enabled: true,
          client_id: clientId.trim(),
          client_secret: clientSecret || undefined,
        },
        configId ?? undefined,
      );
      if ("error" in result) {
        toast({
          variant: "destructive",
          title: "Could not save Slack app settings",
          description: result.error,
        });
        return;
      }
      setConfigId(result.id);
      setHasSecret(result.attributes.has_client_secret);
      setClientSecret("");
      toast({
        title: "Slack app saved",
        description: "You can connect a workspace with Add to Slack.",
      });
      router.refresh();
    } finally {
      setIsSaving(false);
    }
  };

  const onDelete = async () => {
    if (!configId) return;
    setIsDeleting(true);
    try {
      const result = await deleteSlackAppConfig(configId);
      if ("error" in result) {
        toast({
          variant: "destructive",
          title: "Could not remove Slack app settings",
          description: result.error,
        });
        return;
      }
      setConfigId(null);
      setClientId("");
      setHasSecret(false);
      setClientSecret("");
      toast({
        title: "Slack app settings removed",
        description: "Workspace installs will not work until you save them again.",
      });
      router.refresh();
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className="flex max-w-xl flex-col gap-4">
      <p className="text-sm text-gray-600 dark:text-gray-300">
        Create a Slack app at{" "}
        <a
          className="underline"
          href="https://api.slack.com/apps"
          target="_blank"
          rel="noopener noreferrer"
        >
          api.slack.com/apps
        </a>
        , enable OAuth with scopes{" "}
        <code className="text-xs">channels:read,groups:read,chat:write,channels:join</code>
        , and set the Redirect URL to:
      </p>
      <code className="break-all rounded border px-3 py-2 text-xs">
        {redirectUri}
      </code>

      <div className="flex flex-col gap-2">
        <Label htmlFor="slack-client-id">Client ID</Label>
        <Input
          id="slack-client-id"
          value={clientId}
          onChange={(event) => setClientId(event.target.value)}
          autoComplete="off"
        />
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="slack-client-secret">
          Client Secret
          {hasSecret ? " (leave blank to keep current)" : ""}
        </Label>
        <Input
          id="slack-client-secret"
          type="password"
          value={clientSecret}
          onChange={(event) => setClientSecret(event.target.value)}
          autoComplete="new-password"
        />
      </div>

      <div className="flex flex-wrap gap-2 pt-2">
        <Button
          onClick={onSave}
          disabled={
            isSaving || !clientId.trim() || (!hasSecret && !clientSecret.trim())
          }
        >
          {isSaving ? "Saving..." : "Save Slack app"}
        </Button>
        {configId && (
          <Button
            variant="destructive"
            onClick={onDelete}
            disabled={isDeleting}
          >
            {isDeleting ? "Removing..." : "Remove"}
          </Button>
        )}
      </div>
    </div>
  );
};
