"use client";

import { Sparkles } from "lucide-react";
import { type ChangeEvent, useState } from "react";

import { generateSbomFromDescription } from "@/cloudsneeker/actions/sbom";
import { FormField } from "@/cloudsneeker/components/form-layout";
import {
  buildCycloneDxSbom,
  isSbomDocument,
  type ParsedComponents,
  parseManifest,
  SBOM_DESCRIPTION_MAX_LENGTH,
  SBOM_MANIFEST_FILES,
  SBOM_UPLOAD_ACCEPT,
} from "@/cloudsneeker/lib/sbom-builder";
import { Button, Input, Textarea } from "@/components/shadcn";

const DESCRIBE_PLACEHOLDER =
  "Our API runs Django 3.2.4 and requests 2.25.1; the web app uses React 17.0.2 and lodash 4.17.20; the billing service uses Log4j 2.14.1.";

interface SbomSourceFieldsProps {
  value: string;
  onChange: (sbom: string) => void;
  error?: string;
}

const summary = ({ components, skipped }: ParsedComponents): string => {
  const added = `Added ${components.length} component${components.length === 1 ? "" : "s"}.`;
  return skipped.length > 0
    ? `${added} Skipped without an exact version: ${skipped.join(", ")}.`
    : added;
};

// FileReader rather than `Blob.text()`, which older browsers lack.
const readFileText = (file: File): Promise<string> =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });

export const SbomSourceFields = ({
  value,
  onChange,
  error,
}: SbomSourceFieldsProps) => {
  const [description, setDescription] = useState("");
  const [generating, setGenerating] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [sourceError, setSourceError] = useState<string | null>(null);

  const report = (message: string | null, failure: string | null) => {
    setNotice(message);
    setSourceError(failure);
  };

  const onFileSelected = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const text = await readFileText(file);
    if (isSbomDocument(text)) {
      onChange(text);
      report(`Loaded ${file.name}.`, null);
      return;
    }
    let parsed: ParsedComponents | null = null;
    try {
      parsed = parseManifest(file.name, text);
    } catch {
      parsed = null;
    }
    if (!parsed || parsed.components.length === 0) {
      event.target.value = "";
      report(
        null,
        parsed
          ? `No pinned versions found in ${file.name}.`
          : `Upload a CycloneDX or SPDX document, or one of: ${SBOM_MANIFEST_FILES.join(", ")}.`,
      );
      return;
    }
    onChange(buildCycloneDxSbom(parsed.components));
    report(`${file.name}: ${summary(parsed)}`, null);
  };

  const onGenerate = async () => {
    setGenerating(true);
    report(null, null);
    const result = await generateSbomFromDescription(description);
    setGenerating(false);
    if ("error" in result) {
      report(null, result.error);
      return;
    }
    onChange(result.sbom);
    report(`${summary(result)} Review the SBOM before saving.`, null);
  };

  return (
    <>
      <FormField
        id="trivy-sbom-file"
        label="Upload a file"
        optional
        help={`A CycloneDX or SPDX document, or a dependency file to convert (${SBOM_MANIFEST_FILES.join(", ")}).`}
      >
        <Input
          id="trivy-sbom-file"
          type="file"
          accept={SBOM_UPLOAD_ACCEPT}
          onChange={onFileSelected}
        />
      </FormField>

      <FormField
        id="trivy-sbom-describe"
        label="Describe your components"
        optional
        help="Seeker AI lists the packages and versions you name. Only stated versions are used."
      >
        <div className="flex flex-col gap-2">
          <Textarea
            id="trivy-sbom-describe"
            rows={3}
            maxLength={SBOM_DESCRIPTION_MAX_LENGTH}
            placeholder={DESCRIBE_PLACEHOLDER}
            value={description}
            onChange={(event) => setDescription(event.target.value)}
          />
          <div>
            <Button
              type="button"
              variant="outline"
              disabled={generating || !description.trim()}
              onClick={onGenerate}
            >
              <Sparkles aria-hidden="true" />
              {generating ? "Generating…" : "Generate with Seeker AI"}
            </Button>
          </div>
        </div>
      </FormField>

      {notice ? (
        <p role="status" className="text-text-neutral-secondary text-sm">
          {notice}
        </p>
      ) : null}

      <FormField
        id="trivy-sbom"
        label="SBOM content"
        help="Paste a CycloneDX or SPDX document, or build one above."
        error={sourceError ?? error}
      >
        <Textarea
          id="trivy-sbom"
          rows={8}
          className="font-mono text-xs"
          value={value}
          onChange={(event) => onChange(event.target.value)}
        />
      </FormField>
    </>
  );
};
