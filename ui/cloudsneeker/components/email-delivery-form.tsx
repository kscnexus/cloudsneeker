"use client";

import { useState } from "react";

import {
  deleteEmailDeliveryConfig,
  saveEmailDeliveryConfig,
  testEmailDeliveryConfig,
  type EmailDeliveryConfigResource,
} from "@/cloudsneeker/actions/email-delivery";
import { Button, Input, Label } from "@/components/shadcn";
import { useToast } from "@/components/shadcn/toast/use-toast";

interface EmailDeliveryFormProps {
  initial: EmailDeliveryConfigResource | null;
}

export const EmailDeliveryForm = ({ initial }: EmailDeliveryFormProps) => {
  const { toast } = useToast();
  const [configId, setConfigId] = useState(initial?.id ?? null);
  const [enabled, setEnabled] = useState(initial?.attributes.enabled ?? true);
  const [host, setHost] = useState(initial?.attributes.host ?? "");
  const [port, setPort] = useState(String(initial?.attributes.port ?? 587));
  const [useTls, setUseTls] = useState(initial?.attributes.use_tls ?? true);
  const [useSsl, setUseSsl] = useState(initial?.attributes.use_ssl ?? false);
  const [username, setUsername] = useState(initial?.attributes.username ?? "");
  const [password, setPassword] = useState("");
  const [fromEmail, setFromEmail] = useState(
    initial?.attributes.from_email ?? "",
  );
  const [hasPassword, setHasPassword] = useState(
    initial?.attributes.has_password ?? false,
  );
  const [isSaving, setIsSaving] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  const onSave = async () => {
    setIsSaving(true);
    try {
      const result = await saveEmailDeliveryConfig(
        {
          enabled,
          host: host.trim(),
          port: Number(port) || 587,
          use_tls: useTls,
          use_ssl: useSsl,
          username: username.trim(),
          password: password || undefined,
          from_email: fromEmail.trim(),
        },
        configId ?? undefined,
      );
      if ("error" in result) {
        toast({
          variant: "destructive",
          title: "Could not save SMTP settings",
          description: result.error,
        });
        return;
      }
      setConfigId(result.id);
      setHasPassword(result.attributes.has_password);
      setPassword("");
      toast({
        title: "SMTP settings saved",
        description: "Alert emails will use this server when rules match.",
      });
    } finally {
      setIsSaving(false);
    }
  };

  const onTest = async () => {
    if (!configId) {
      toast({
        variant: "destructive",
        title: "Save SMTP settings first",
        description: "A test send needs a stored configuration.",
      });
      return;
    }
    setIsTesting(true);
    try {
      const result = await testEmailDeliveryConfig(configId);
      if ("error" in result) {
        toast({
          variant: "destructive",
          title: "SMTP test failed",
          description: result.error,
        });
        return;
      }
      toast({
        title: "Test email sent",
        description: result.sent_to
          ? `Sent to ${result.sent_to}.`
          : "Check your inbox.",
      });
    } finally {
      setIsTesting(false);
    }
  };

  const onDelete = async () => {
    if (!configId) return;
    setIsDeleting(true);
    try {
      const result = await deleteEmailDeliveryConfig(configId);
      if ("error" in result) {
        toast({
          variant: "destructive",
          title: "Could not delete SMTP settings",
          description: result.error,
        });
        return;
      }
      setConfigId(null);
      setHasPassword(false);
      setPassword("");
      toast({
        title: "SMTP settings removed",
        description: "Alert emails will not send until you configure SMTP again.",
      });
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className="flex max-w-xl flex-col gap-4">
      <div className="flex items-center gap-2">
        <input
          id="email-enabled"
          type="checkbox"
          checked={enabled}
          onChange={(event) => setEnabled(event.target.checked)}
        />
        <Label htmlFor="email-enabled">Enabled</Label>
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="email-host">SMTP host</Label>
        <Input
          id="email-host"
          value={host}
          onChange={(event) => setHost(event.target.value)}
          placeholder="smtp.example.com"
          autoComplete="off"
        />
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="email-port">Port</Label>
        <Input
          id="email-port"
          type="number"
          value={port}
          onChange={(event) => setPort(event.target.value)}
          min={1}
          max={65535}
        />
      </div>

      <div className="flex flex-wrap gap-4">
        <div className="flex items-center gap-2">
          <input
            id="email-tls"
            type="checkbox"
            checked={useTls}
            onChange={(event) => {
              setUseTls(event.target.checked);
              if (event.target.checked) setUseSsl(false);
            }}
          />
          <Label htmlFor="email-tls">Use STARTTLS</Label>
        </div>
        <div className="flex items-center gap-2">
          <input
            id="email-ssl"
            type="checkbox"
            checked={useSsl}
            onChange={(event) => {
              setUseSsl(event.target.checked);
              if (event.target.checked) setUseTls(false);
            }}
          />
          <Label htmlFor="email-ssl">Use SSL</Label>
        </div>
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="email-username">Username</Label>
        <Input
          id="email-username"
          value={username}
          onChange={(event) => setUsername(event.target.value)}
          autoComplete="off"
        />
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="email-password">
          Password{hasPassword ? " (leave blank to keep current)" : ""}
        </Label>
        <Input
          id="email-password"
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          autoComplete="new-password"
        />
      </div>

      <div className="flex flex-col gap-2">
        <Label htmlFor="email-from">From address</Label>
        <Input
          id="email-from"
          type="email"
          value={fromEmail}
          onChange={(event) => setFromEmail(event.target.value)}
          placeholder="alerts@example.com"
        />
      </div>

      <div className="flex flex-wrap gap-2 pt-2">
        <Button onClick={onSave} disabled={isSaving || !host || !fromEmail}>
          {isSaving ? "Saving..." : "Save"}
        </Button>
        <Button
          variant="secondary"
          onClick={onTest}
          disabled={isTesting || !configId}
        >
          {isTesting ? "Sending..." : "Send test email"}
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
