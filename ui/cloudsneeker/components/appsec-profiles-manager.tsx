"use client";

import { useState } from "react";

import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
import type {
  AppSecCapabilities,
  AppSecProfileAttributes,
  AppSecResource,
} from "@/cloudsneeker/types/appsec";
import { Button } from "@/components/shadcn";
import { Badge } from "@/components/shadcn/badge/badge";

import { AppSecProfileForm } from "./appsec-profile-form";
import {
  TABLE_CLASS,
  TABLE_WRAPPER_CLASS,
  TD_CLASS,
  TD_PRIMARY_CLASS,
  TH_CLASS,
} from "./appsec-ui";
import { SectionCard } from "./section-card";

interface AppSecProfilesManagerProps {
  profiles: AppSecResource<AppSecProfileAttributes>[];
  capabilities: AppSecCapabilities;
  canManage: boolean;
}

const EDITOR_MODE = {
  NONE: "none",
  CREATE: "create",
  CLONE: "clone",
  EDIT: "edit",
} as const;
type EditorMode = (typeof EDITOR_MODE)[keyof typeof EDITOR_MODE];

interface EditorState {
  mode: EditorMode;
  profile?: AppSecResource<AppSecProfileAttributes>;
}

const optionSummary = (options: Record<string, unknown>): string => {
  const extras = Object.keys(options).filter((key) => key !== "scanners");
  return extras.length === 0
    ? "Defaults"
    : extras.map((key) => key.replace(/_/g, " ")).join(", ");
};

/** Built-in and custom scan profiles with create, clone, edit and delete. */
export const AppSecProfilesManager = ({
  profiles,
  capabilities,
  canManage,
}: AppSecProfilesManagerProps) => {
  const [editor, setEditor] = useState<EditorState>({ mode: EDITOR_MODE.NONE });
  const scannerLabel = (id: string) =>
    capabilities.scanners.find((scanner) => scanner.id === id)?.label ?? id;
  const close = () => setEditor({ mode: EDITOR_MODE.NONE });

  return (
    <div className="flex flex-col gap-6">
      <SectionCard
        title="Scan profiles"
        description="A profile is a reusable set of scanners and options. An asset uses its own profile, else its application's, else the organization default for its type."
        actions={
          canManage ? (
            <Button
              size="sm"
              onClick={() => setEditor({ mode: EDITOR_MODE.CREATE })}
            >
              New profile
            </Button>
          ) : null
        }
      >
        <div className={TABLE_WRAPPER_CLASS}>
          <table className={TABLE_CLASS}>
            <thead>
              <tr>
                <th scope="col" className={TH_CLASS}>
                  Profile
                </th>
                <th scope="col" className={TH_CLASS}>
                  Scanners
                </th>
                <th scope="col" className={TH_CLASS}>
                  Target types
                </th>
                <th scope="col" className={TH_CLASS}>
                  Options set
                </th>
                <th scope="col" className={TH_CLASS}>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {profiles.map((profile) => {
                const { attributes } = profile;
                const scanners = Array.isArray(attributes.options.scanners)
                  ? (attributes.options.scanners as string[])
                  : [];
                return (
                  <tr key={profile.id}>
                    <td className={TD_PRIMARY_CLASS}>
                      <span className="font-medium">{attributes.name}</span>{" "}
                      {attributes.builtin ? (
                        <Badge variant="tag">Built-in</Badge>
                      ) : attributes.enabled ? null : (
                        <Badge variant="warning">Disabled</Badge>
                      )}
                      <p className="text-text-neutral-secondary text-xs">
                        {attributes.description}
                      </p>
                    </td>
                    <td className={TD_CLASS}>
                      {scanners.map(scannerLabel).join(", ")}
                    </td>
                    <td className={TD_CLASS}>
                      {attributes.target_types.length === 0
                        ? "All"
                        : attributes.target_types
                            .map(labelForTrivyMode)
                            .join(", ")}
                    </td>
                    <td className={TD_CLASS}>
                      {optionSummary(attributes.options)}
                    </td>
                    <td className={TD_CLASS}>
                      {canManage ? (
                        <div className="flex justify-end gap-2">
                          <Button
                            size="xs"
                            variant="outline"
                            onClick={() =>
                              setEditor({ mode: EDITOR_MODE.CLONE, profile })
                            }
                          >
                            Clone
                          </Button>
                          {attributes.builtin ? null : (
                            <Button
                              size="xs"
                              variant="outline"
                              onClick={() =>
                                setEditor({ mode: EDITOR_MODE.EDIT, profile })
                              }
                            >
                              Edit
                            </Button>
                          )}
                        </div>
                      ) : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </SectionCard>

      {editor.mode !== EDITOR_MODE.NONE ? (
        <AppSecProfileForm
          key={`${editor.mode}-${editor.profile?.id ?? "new"}`}
          capabilities={capabilities}
          profileId={
            editor.mode === EDITOR_MODE.EDIT ? editor.profile?.id : undefined
          }
          initial={editor.profile?.attributes}
          onDone={close}
        />
      ) : null}
    </div>
  );
};
