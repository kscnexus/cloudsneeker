"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  createAppSecProfile,
  deleteAppSecProfile,
  updateAppSecProfile,
} from "@/cloudsneeker/actions/appsec";
import { actionError } from "@/cloudsneeker/lib/appsec";
import {
  FORM_CHECK_CLASS,
  FORM_CHOICE_CLASS,
  FORM_CLASS,
  FORM_SELECT_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import type {
  AppSecCapabilities,
  AppSecOptionSpec,
  AppSecProfileAttributes,
} from "@/cloudsneeker/types/appsec";
import { Button, Input, Textarea } from "@/components/shadcn";

import {
  FormActions,
  FormAlert,
  FormChoiceGroup,
  FormField,
} from "./form-layout";
import { SectionCard } from "./section-card";

interface AppSecProfileFormProps {
  capabilities: AppSecCapabilities;
  /** Profile being edited; omit to create. */
  profileId?: string;
  /** Values to start from (the edited profile, or one being cloned). */
  initial?: AppSecProfileAttributes;
  onDone?: () => void;
}

type OptionValues = Record<string, unknown>;

/** Options that belong to a target, not to a reusable profile. */
const TARGET_ONLY_OPTIONS: readonly string[] = ["branch", "tag", "commit"];

const linesOf = (value: unknown): string =>
  Array.isArray(value) ? value.join("\n") : "";

const toLines = (value: string): string[] =>
  value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);

/**
 * Create or edit a scan profile. The scanner and option lists come from the
 * capability matrix and shrink to what the selected target types accept, so
 * a profile cannot hold an option no selected target supports.
 */
export const AppSecProfileForm = ({
  capabilities,
  profileId,
  initial,
  onDone,
}: AppSecProfileFormProps) => {
  const router = useRouter();
  const [name, setName] = useState(
    profileId ? (initial?.name ?? "") : initial ? `${initial.name} (copy)` : "",
  );
  const [description, setDescription] = useState(initial?.description ?? "");
  const [targetTypes, setTargetTypes] = useState<string[]>(
    initial?.target_types ?? [],
  );
  const [options, setOptions] = useState<OptionValues>(
    initial?.options ?? { scanners: ["vuln", "misconfig", "secret"] },
  );
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const targets = capabilities.targets.filter(
    (target) => targetTypes.length === 0 || targetTypes.includes(target.id),
  );
  const scannerIds = capabilities.scanners
    .map((scanner) => scanner.id)
    .filter((id) => targets.some((target) => target.scanners.includes(id)));
  const selectedScanners = Array.isArray(options.scanners)
    ? (options.scanners as string[])
    : [];
  const optionNames = Object.keys(capabilities.options).filter(
    (optionName) =>
      !TARGET_ONLY_OPTIONS.includes(optionName) &&
      targets.some((target) => target.options.includes(optionName)) &&
      (!capabilities.options[optionName].scanner ||
        selectedScanners.includes(
          capabilities.options[optionName].scanner as string,
        )),
  );

  const setOption = (optionName: string, value: unknown) =>
    setOptions((current) => {
      const next = { ...current };
      const empty =
        value === undefined ||
        value === "" ||
        value === false ||
        (Array.isArray(value) && value.length === 0);
      if (empty) delete next[optionName];
      else next[optionName] = value;
      return next;
    });

  const toggleIn = (optionName: string, item: string) => {
    const current = Array.isArray(options[optionName])
      ? (options[optionName] as string[])
      : [];
    setOption(
      optionName,
      current.includes(item)
        ? current.filter((value) => value !== item)
        : [...current, item],
    );
  };

  const toggleTargetType = (targetId: string) =>
    setTargetTypes((current) =>
      current.includes(targetId)
        ? current.filter((value) => value !== targetId)
        : [...current, targetId],
    );

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (name.trim().length < 3) {
      setError("Give the profile a name of at least 3 characters.");
      return;
    }
    const scanners = selectedScanners.filter((id) => scannerIds.includes(id));
    if (scanners.length === 0) {
      setError("Select at least one scanner.");
      return;
    }
    const cleaned: OptionValues = { scanners };
    for (const optionName of optionNames) {
      if (options[optionName] !== undefined) {
        cleaned[optionName] = options[optionName];
      }
    }
    setSaving(true);
    setError(null);
    const attributes = {
      name: name.trim(),
      description,
      target_types: targetTypes,
      options: cleaned,
      enabled,
    };
    const result = profileId
      ? await updateAppSecProfile(profileId, attributes)
      : await createAppSecProfile(attributes);
    setSaving(false);
    const failure = actionError(result);
    if (failure) {
      setError(failure);
      return;
    }
    router.refresh();
    onDone?.();
  };

  const onDelete = async () => {
    if (!profileId || !window.confirm("Delete this scan profile?")) return;
    setSaving(true);
    const result = await deleteAppSecProfile(profileId);
    setSaving(false);
    const failure = actionError(result);
    if (failure) {
      setError(failure);
      return;
    }
    router.refresh();
    onDone?.();
  };

  const renderOption = (optionName: string, spec: AppSecOptionSpec) => {
    const id = `profile-option-${optionName}`;
    const value = options[optionName];
    if (spec.type === "bool") {
      return (
        <label key={optionName} className={FORM_CHOICE_CLASS}>
          <input
            type="checkbox"
            className={FORM_CHECK_CLASS}
            checked={value === true}
            onChange={(event) => setOption(optionName, event.target.checked)}
          />
          <span>
            {spec.label}
            {spec.help ? (
              <span className="text-text-neutral-tertiary block text-xs">
                {spec.help}
              </span>
            ) : null}
          </span>
        </label>
      );
    }
    if (spec.type === "choices") {
      return (
        <FormChoiceGroup key={optionName} legend={spec.label} help={spec.help}>
          <div className="flex flex-wrap gap-x-4 gap-y-1">
            {(spec.choices ?? []).map((choice) => (
              <label key={choice} className={FORM_CHOICE_CLASS}>
                <input
                  type="checkbox"
                  className={FORM_CHECK_CLASS}
                  checked={Array.isArray(value) && value.includes(choice)}
                  onChange={() => toggleIn(optionName, choice)}
                />
                <span>{choice}</span>
              </label>
            ))}
          </div>
        </FormChoiceGroup>
      );
    }
    if (spec.type === "choice") {
      return (
        <FormField key={optionName} id={id} label={spec.label} help={spec.help}>
          <select
            id={id}
            className={FORM_SELECT_CLASS}
            value={typeof value === "string" ? value : ""}
            onChange={(event) => setOption(optionName, event.target.value)}
          >
            <option value="">Engine default</option>
            {(spec.choices ?? []).map((choice) => (
              <option key={choice} value={choice}>
                {choice}
              </option>
            ))}
          </select>
        </FormField>
      );
    }
    if (spec.type === "int" || spec.type === "float") {
      return (
        <FormField
          key={optionName}
          id={id}
          label={spec.label}
          help={`Between ${spec.min} and ${spec.max}. Empty uses the default.`}
        >
          <Input
            id={id}
            type="number"
            min={spec.min}
            max={spec.max}
            step={spec.type === "float" ? "0.05" : "1"}
            value={typeof value === "number" ? value : ""}
            onChange={(event) =>
              setOption(
                optionName,
                event.target.value === ""
                  ? undefined
                  : Number(event.target.value),
              )
            }
          />
        </FormField>
      );
    }
    if (spec.type === "platform") {
      return (
        <FormField
          key={optionName}
          id={id}
          label={spec.label}
          help="For example linux/amd64."
        >
          <Input
            id={id}
            value={typeof value === "string" ? value : ""}
            onChange={(event) =>
              setOption(optionName, event.target.value.trim())
            }
          />
        </FormField>
      );
    }
    // globs, strings, k8s_names: one entry per line.
    return (
      <FormField
        key={optionName}
        id={id}
        label={spec.label}
        help={spec.help ?? "One entry per line."}
      >
        <Textarea
          id={id}
          rows={2}
          value={linesOf(value)}
          onChange={(event) =>
            setOption(optionName, toLines(event.target.value))
          }
        />
      </FormField>
    );
  };

  return (
    <form onSubmit={onSubmit} className={FORM_CLASS} noValidate>
      <SectionCard title={profileId ? "Edit scan profile" : "New scan profile"}>
        <FormField id="profile-name" label="Name">
          <Input
            id="profile-name"
            value={name}
            maxLength={100}
            onChange={(event) => setName(event.target.value)}
          />
        </FormField>
        <FormField id="profile-description" label="Description" optional>
          <Textarea
            id="profile-description"
            rows={2}
            value={description}
            maxLength={2000}
            onChange={(event) => setDescription(event.target.value)}
          />
        </FormField>
        <FormChoiceGroup
          legend="Target types"
          help="Leave all unchecked to allow every type. A scanner or option a type does not support is dropped for that type when a scan starts."
        >
          <div className="flex flex-wrap gap-x-4 gap-y-1">
            {capabilities.targets.map((target) => (
              <label key={target.id} className={FORM_CHOICE_CLASS}>
                <input
                  type="checkbox"
                  className={FORM_CHECK_CLASS}
                  checked={targetTypes.includes(target.id)}
                  onChange={() => toggleTargetType(target.id)}
                />
                <span>{target.label}</span>
              </label>
            ))}
          </div>
        </FormChoiceGroup>
        <FormChoiceGroup legend="Scanners">
          <div className="flex flex-wrap gap-x-4 gap-y-1">
            {capabilities.scanners
              .filter((scanner) => scannerIds.includes(scanner.id))
              .map((scanner) => (
                <label key={scanner.id} className={FORM_CHOICE_CLASS}>
                  <input
                    type="checkbox"
                    className={FORM_CHECK_CLASS}
                    checked={selectedScanners.includes(scanner.id)}
                    onChange={() => toggleIn("scanners", scanner.id)}
                  />
                  <span>{scanner.label}</span>
                </label>
              ))}
          </div>
        </FormChoiceGroup>
        {profileId ? (
          <label className={FORM_CHOICE_CLASS}>
            <input
              type="checkbox"
              className={FORM_CHECK_CLASS}
              checked={enabled}
              onChange={(event) => setEnabled(event.target.checked)}
            />
            <span>Enabled (a disabled profile fails scans that use it)</span>
          </label>
        ) : null}
      </SectionCard>

      <SectionCard
        title="Options"
        description="Only options the selected target types and scanners accept are listed."
      >
        {optionNames.map((optionName) =>
          renderOption(optionName, capabilities.options[optionName]),
        )}
      </SectionCard>

      <FormAlert message={error} />
      <FormActions>
        <Button type="submit" disabled={saving}>
          {saving ? "Saving…" : profileId ? "Save profile" : "Create profile"}
        </Button>
        {onDone ? (
          <Button type="button" variant="ghost" onClick={onDone}>
            Cancel
          </Button>
        ) : null}
        {profileId ? (
          <Button
            type="button"
            variant="destructive"
            onClick={onDelete}
            disabled={saving}
          >
            Delete
          </Button>
        ) : null}
      </FormActions>
    </form>
  );
};
