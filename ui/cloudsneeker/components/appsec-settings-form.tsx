"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { updateAppSecSettings } from "@/cloudsneeker/actions/appsec";
import { actionError } from "@/cloudsneeker/lib/appsec";
import { FORM_SELECT_CLASS } from "@/cloudsneeker/lib/ui-classes";
import type {
  AppSecCapabilityTarget,
  AppSecRetention,
  AppSecSettings,
} from "@/cloudsneeker/types/appsec";
import { Button, Input } from "@/components/shadcn";

import type { AppSecProfileOption } from "./appsec-application-form";
import { FormActions, FormAlert, FormField } from "./form-layout";

interface AppSecSettingsFormProps {
  settings: AppSecSettings;
  targets: AppSecCapabilityTarget[];
  profiles: AppSecProfileOption[];
}

const SLA_SEVERITIES = ["critical", "high", "medium", "low"] as const;
const THRESHOLDS = ["urgent", "high", "medium"] as const;
const RETENTION_FIELDS: {
  key: keyof AppSecRetention;
  label: string;
  help: string;
}[] = [
  {
    key: "sbom_versions",
    label: "SBOM versions kept per asset",
    help: "Older inventories are deleted when a new one is stored.",
  },
  {
    key: "raw_artifact_days",
    label: "Raw scan reports (days)",
    help: "After this, a scan can no longer be exported as SARIF or SPDX.",
  },
  {
    key: "fixed_findings_days",
    label: "Fixed findings (days)",
    help: "Fixed findings older than this are deleted.",
  },
];

const record = (value: unknown): Record<string, number> =>
  value !== null && typeof value === "object"
    ? (value as Record<string, number>)
    : {};

const label = (value: string) => value.charAt(0).toUpperCase() + value.slice(1);

/** Tenant settings: remediation deadlines, priority thresholds, retention. */
export const AppSecSettingsForm = ({
  settings,
  targets,
  profiles,
}: AppSecSettingsFormProps) => {
  const router = useRouter();
  const [sla, setSla] = useState<Record<string, number>>(settings.sla_days);
  const [thresholds, setThresholds] = useState<Record<string, number>>(
    record(settings.risk.thresholds),
  );
  const [retention, setRetention] = useState<AppSecRetention>(
    settings.retention,
  );
  const [defaults, setDefaults] = useState<Record<string, string>>(
    settings.default_profiles,
  );
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);

  const number = (value: string): number =>
    value === "" ? 0 : Number.parseInt(value, 10);

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError(null);
    setSaved(false);
    const result = await updateAppSecSettings({
      sla_days: sla,
      risk: { ...settings.risk_overrides, thresholds },
      retention,
      default_profiles: defaults,
    });
    setSaving(false);
    const failure = actionError(result);
    if (failure) {
      setError(failure);
      return;
    }
    setSaved(true);
    router.refresh();
  };

  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-6" noValidate>
      <fieldset className="flex flex-col gap-3">
        <legend className="text-text-neutral-primary mb-2 text-sm font-semibold">
          Remediation deadlines (days from first detection)
        </legend>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          {SLA_SEVERITIES.map((severity) => (
            <FormField
              key={severity}
              id={`sla-${severity}`}
              label={label(severity)}
              help={`Default ${settings.sla_defaults[severity]}`}
            >
              <Input
                id={`sla-${severity}`}
                type="number"
                min={1}
                max={3650}
                value={sla[severity] ?? ""}
                onChange={(event) =>
                  setSla({ ...sla, [severity]: number(event.target.value) })
                }
              />
            </FormField>
          ))}
        </div>
      </fieldset>

      <fieldset className="flex flex-col gap-3">
        <legend className="text-text-neutral-primary mb-2 text-sm font-semibold">
          Priority thresholds (score 0 to 100)
        </legend>
        <p className="text-text-neutral-tertiary text-xs">
          A finding takes the highest priority whose threshold its score
          reaches. Changing these recalculates open findings; scanner severity
          stays as reported.
        </p>
        <div className="grid grid-cols-3 gap-3">
          {THRESHOLDS.map((name) => (
            <FormField
              key={name}
              id={`threshold-${name}`}
              label={label(name)}
              help={`Default ${record(settings.risk_defaults.thresholds)[name]}`}
            >
              <Input
                id={`threshold-${name}`}
                type="number"
                min={0}
                max={100}
                value={thresholds[name] ?? ""}
                onChange={(event) =>
                  setThresholds({
                    ...thresholds,
                    [name]: number(event.target.value),
                  })
                }
              />
            </FormField>
          ))}
        </div>
      </fieldset>

      <fieldset className="flex flex-col gap-3">
        <legend className="text-text-neutral-primary mb-2 text-sm font-semibold">
          Default scan profile by target type
        </legend>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
          {targets.map((target) => (
            <FormField
              key={target.id}
              id={`default-profile-${target.id}`}
              label={target.label}
            >
              <select
                id={`default-profile-${target.id}`}
                className={FORM_SELECT_CLASS}
                value={defaults[target.id] ?? ""}
                onChange={(event) =>
                  setDefaults({ ...defaults, [target.id]: event.target.value })
                }
              >
                <option value="">Balanced (built-in default)</option>
                {profiles.map((profile) => (
                  <option key={profile.ref} value={profile.ref}>
                    {profile.name}
                  </option>
                ))}
              </select>
            </FormField>
          ))}
        </div>
      </fieldset>

      <fieldset className="flex flex-col gap-3">
        <legend className="text-text-neutral-primary mb-2 text-sm font-semibold">
          Retention
        </legend>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          {RETENTION_FIELDS.map((field) => (
            <FormField
              key={field.key}
              id={`retention-${field.key}`}
              label={field.label}
              help={field.help}
            >
              <Input
                id={`retention-${field.key}`}
                type="number"
                min={1}
                value={retention[field.key] ?? ""}
                onChange={(event) =>
                  setRetention({
                    ...retention,
                    [field.key]: number(event.target.value),
                  })
                }
              />
            </FormField>
          ))}
        </div>
      </fieldset>

      <FormAlert message={error} />
      {saved ? (
        <p role="status" className="text-text-neutral-secondary text-sm">
          Settings saved.
        </p>
      ) : null}
      <FormActions>
        <Button type="submit" disabled={saving}>
          {saving ? "Saving…" : "Save settings"}
        </Button>
      </FormActions>
    </form>
  );
};
