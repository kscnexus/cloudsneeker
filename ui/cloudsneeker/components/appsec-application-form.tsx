"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  createAppSecApplication,
  deleteAppSecApplication,
  updateAppSecApplication,
} from "@/cloudsneeker/actions/appsec";
import {
  actionError,
  APPSEC_SEGMENT,
  appSecApplicationHref,
  APPSEC_CRITICALITIES,
  APPSEC_ENVIRONMENTS,
} from "@/cloudsneeker/lib/appsec";
import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
import {
  FORM_CHECK_CLASS,
  FORM_CHOICE_CLASS,
  FORM_CLASS,
  FORM_SELECT_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import type { AppSecApplicationAttributes } from "@/cloudsneeker/types/appsec";
import { Button, Input, Textarea } from "@/components/shadcn";

import {
  FormActions,
  FormAlert,
  FormChoiceGroup,
  FormField,
} from "./form-layout";
import { SectionCard } from "./section-card";

export interface AppSecTargetOption {
  id: string;
  name: string;
  mode: string;
  applicationId: string | null;
  applicationName: string | null;
}

export interface AppSecProfileOption {
  ref: string;
  name: string;
}

interface AppSecApplicationFormProps {
  applicationId?: string;
  initial?: AppSecApplicationAttributes;
  targets: AppSecTargetOption[];
  profiles: AppSecProfileOption[];
}

const CRITICALITY = APPSEC_CRITICALITIES;
const ENVIRONMENT = APPSEC_ENVIRONMENTS;
const EXPOSURE = {
  UNKNOWN: "unknown",
  YES: "yes",
  NO: "no",
} as const;

const label = (value: string) => value.charAt(0).toUpperCase() + value.slice(1);

export const AppSecApplicationForm = ({
  applicationId,
  initial,
  targets,
  profiles,
}: AppSecApplicationFormProps) => {
  const router = useRouter();
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [owner, setOwner] = useState(initial?.owner ?? "");
  const [criticality, setCriticality] = useState(
    initial?.criticality ?? "medium",
  );
  const [environment, setEnvironment] = useState(
    initial?.environment ?? "unknown",
  );
  const [exposure, setExposure] = useState<string>(
    initial?.internet_exposed === true
      ? EXPOSURE.YES
      : initial?.internet_exposed === false
        ? EXPOSURE.NO
        : EXPOSURE.UNKNOWN,
  );
  const [profile, setProfile] = useState(initial?.default_profile_ref ?? "");
  const [selected, setSelected] = useState<string[]>(
    targets
      .filter(
        (target) => applicationId && target.applicationId === applicationId,
      )
      .map((target) => target.id),
  );
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const toggle = (targetId: string) =>
    setSelected((current) =>
      current.includes(targetId)
        ? current.filter((value) => value !== targetId)
        : [...current, targetId],
    );

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (name.trim().length < 2) {
      setError("Give the application a name of at least 2 characters.");
      return;
    }
    setSaving(true);
    setError(null);
    const attributes = {
      name: name.trim(),
      description,
      owner,
      criticality,
      environment,
      internet_exposed:
        exposure === EXPOSURE.YES
          ? true
          : exposure === EXPOSURE.NO
            ? false
            : null,
      default_profile_ref: profile,
      target_ids: selected,
    };
    const result = applicationId
      ? await updateAppSecApplication(applicationId, attributes)
      : await createAppSecApplication(attributes);
    setSaving(false);
    const failure = actionError(result);
    if (failure) {
      setError(failure);
      return;
    }
    const id =
      applicationId ?? (result as { data?: { id?: string } })?.data?.id ?? "";
    router.push(
      id
        ? appSecApplicationHref(id)
        : appSecurityHref(APPSEC_SEGMENT.APPLICATIONS),
    );
    router.refresh();
  };

  const onDelete = async () => {
    if (!applicationId) return;
    if (
      !window.confirm(
        "Delete this application? Its assets and findings stay; they become unassigned.",
      )
    )
      return;
    setSaving(true);
    const result = await deleteAppSecApplication(applicationId);
    setSaving(false);
    const failure = actionError(result);
    if (failure) {
      setError(failure);
      return;
    }
    router.push(appSecurityHref(APPSEC_SEGMENT.APPLICATIONS));
    router.refresh();
  };

  return (
    <form onSubmit={onSubmit} className={FORM_CLASS} noValidate>
      <SectionCard title="Application">
        <FormField id="application-name" label="Name">
          <Input
            id="application-name"
            value={name}
            maxLength={100}
            onChange={(event) => setName(event.target.value)}
          />
        </FormField>
        <FormField id="application-description" label="Description" optional>
          <Textarea
            id="application-description"
            value={description}
            rows={2}
            maxLength={2000}
            onChange={(event) => setDescription(event.target.value)}
          />
        </FormField>
        <FormField
          id="application-owner"
          label="Owner"
          optional
          help="Team or person responsible for fixing findings."
        >
          <Input
            id="application-owner"
            value={owner}
            maxLength={200}
            onChange={(event) => setOwner(event.target.value)}
          />
        </FormField>
      </SectionCard>

      <SectionCard
        title="Risk context"
        description="These facts raise or lower the calculated priority of the application's findings. Scanner severity is not changed."
      >
        <FormField id="application-criticality" label="Business criticality">
          <select
            id="application-criticality"
            className={FORM_SELECT_CLASS}
            value={criticality}
            onChange={(event) => setCriticality(event.target.value)}
          >
            {CRITICALITY.map((value) => (
              <option key={value} value={value}>
                {label(value)}
              </option>
            ))}
          </select>
        </FormField>
        <FormField id="application-environment" label="Environment">
          <select
            id="application-environment"
            className={FORM_SELECT_CLASS}
            value={environment}
            onChange={(event) => setEnvironment(event.target.value)}
          >
            {ENVIRONMENT.map((value) => (
              <option key={value} value={value}>
                {label(value)}
              </option>
            ))}
          </select>
        </FormField>
        <FormField
          id="application-exposure"
          label="Reachable from the internet"
          help="Leave as not stated when you do not know; exposure is then not counted."
        >
          <select
            id="application-exposure"
            className={FORM_SELECT_CLASS}
            value={exposure}
            onChange={(event) => setExposure(event.target.value)}
          >
            <option value={EXPOSURE.UNKNOWN}>Not stated</option>
            <option value={EXPOSURE.YES}>Yes</option>
            <option value={EXPOSURE.NO}>No</option>
          </select>
        </FormField>
      </SectionCard>

      <SectionCard
        title="Assets and scanning"
        description="Repositories, images, archives, SBOMs and clusters that make up the application."
      >
        <FormField
          id="application-profile"
          label="Default scan profile"
          optional
          help="Used by assets that do not choose their own profile."
        >
          <select
            id="application-profile"
            className={FORM_SELECT_CLASS}
            value={profile}
            onChange={(event) => setProfile(event.target.value)}
          >
            <option value="">Organization default</option>
            {profiles.map((item) => (
              <option key={item.ref} value={item.ref}>
                {item.name}
              </option>
            ))}
          </select>
        </FormField>
        <FormChoiceGroup
          legend="Assets"
          help={
            targets.length === 0
              ? "No targets exist yet. Add them from Scans, then assign them here."
              : "An asset belongs to one application; selecting it moves it here."
          }
        >
          {targets.map((target) => (
            <label key={target.id} className={FORM_CHOICE_CLASS}>
              <input
                type="checkbox"
                className={FORM_CHECK_CLASS}
                checked={selected.includes(target.id)}
                onChange={() => toggle(target.id)}
              />
              <span>
                {target.name}{" "}
                <span className="text-text-neutral-tertiary">
                  ({labelForTrivyMode(target.mode)}
                  {target.applicationName &&
                  target.applicationId !== applicationId
                    ? `, now in ${target.applicationName}`
                    : ""}
                  )
                </span>
              </span>
            </label>
          ))}
        </FormChoiceGroup>
      </SectionCard>

      <FormAlert message={error} />
      <FormActions>
        <Button type="submit" disabled={saving}>
          {saving
            ? "Saving…"
            : applicationId
              ? "Save application"
              : "Create application"}
        </Button>
        {applicationId ? (
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
