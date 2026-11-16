"use client";

import { BookOpen, ExternalLink, ShieldCheck } from "lucide-react";
import { useState } from "react";

import {
  getIntegrationSetupGuides,
  getProviderSetupGuides,
  resolveSetupGuideText,
  type SetupGuide,
  type SetupGuideIntegration,
  type SetupGuideUrls,
} from "@/cloudsneeker/lib/setup-guides";
import { Button } from "@/components/shadcn/button/button";
import { CodeSnippet } from "@/components/shadcn/code-snippet/code-snippet";
import { Modal } from "@/components/shadcn/modal";
import { useRuntimeConfig } from "@/hooks/use-runtime-config";
import { useProviderWizardStore } from "@/store/provider-wizard/store";

const MODAL_TITLE = "Setup guide";

interface SetupGuideSectionProps {
  guide: SetupGuide;
  urls: SetupGuideUrls;
}

const SetupGuideSection = ({ guide, urls }: SetupGuideSectionProps) => (
  <section
    aria-label={guide.title}
    data-slot="setup-guide"
    className="flex min-w-0 flex-col gap-4"
  >
    <div className="flex flex-col gap-1">
      <h3 className="text-text-neutral-primary text-sm font-semibold">
        {guide.title}
      </h3>
      <p className="text-text-neutral-secondary text-sm">{guide.summary}</p>
    </div>

    {guide.values && (
      <dl className="border-border-neutral-secondary bg-bg-neutral-tertiary flex flex-col gap-3 rounded-lg border p-4">
        {guide.values.map((item) => (
          <div key={item.label} className="flex min-w-0 flex-col gap-1">
            <dt className="text-text-neutral-primary text-xs font-medium">
              {item.label}
            </dt>
            <dd className="flex min-w-0 flex-col gap-1">
              <CodeSnippet
                value={resolveSetupGuideText(item.value, urls)}
                ariaLabel={`Copy ${item.label}`}
                multiline
                className="w-full"
              />
              {item.note && (
                <span className="text-text-neutral-secondary text-xs">
                  {item.note}
                </span>
              )}
            </dd>
          </div>
        ))}
      </dl>
    )}

    <ol aria-label={`${guide.title} steps`} className="flex flex-col gap-3">
      {guide.steps.map((step, index) => (
        <li key={step.title} className="flex min-w-0 gap-3">
          <span
            aria-hidden="true"
            className="bg-button-tertiary/10 text-button-tertiary flex size-6 shrink-0 items-center justify-center rounded-full text-xs font-semibold"
          >
            {index + 1}
          </span>
          <div className="flex min-w-0 flex-col items-start gap-1">
            <span className="text-text-neutral-primary text-sm font-medium">
              {step.title}
            </span>
            <span className="text-text-neutral-secondary text-xs">
              {resolveSetupGuideText(step.body, urls)}
            </span>
            {step.points && (
              <ul className="text-text-neutral-secondary list-disc pl-4 text-xs">
                {step.points.map((point) => (
                  <li key={point}>{point}</li>
                ))}
              </ul>
            )}
            {step.link && (
              <Button variant="link" size="link-xs" asChild>
                <a
                  href={step.link.href}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <ExternalLink aria-hidden="true" />
                  <span>{step.link.label}</span>
                </a>
              </Button>
            )}
          </div>
        </li>
      ))}
    </ol>

    <div className="border-border-neutral-secondary flex flex-col gap-2 rounded-lg border p-4">
      <span className="text-text-neutral-primary flex items-center gap-2 text-xs font-semibold">
        <ShieldCheck aria-hidden="true" className="size-4 shrink-0" />
        Keep it secure
      </span>
      <ul
        aria-label={`${guide.title} security`}
        className="text-text-neutral-secondary list-disc pl-4 text-xs"
      >
        {guide.security.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </div>
  </section>
);

interface SetupGuideContentProps {
  guides: readonly SetupGuide[];
}

// Mounted only while the dialog is open, so `window` is always available.
const SetupGuideContent = ({ guides }: SetupGuideContentProps) => {
  const { apiBaseUrl } = useRuntimeConfig();
  const urls: SetupGuideUrls = {
    appUrl: window.location.origin,
    apiUrl: apiBaseUrl ?? "",
  };

  return (
    <div className="flex flex-col gap-8">
      {guides.map((guide) => (
        <SetupGuideSection key={guide.title} guide={guide} urls={urls} />
      ))}
    </div>
  );
};

interface SetupGuideButtonProps {
  guides: readonly SetupGuide[];
  className?: string;
}

/** Opens the in-app guide for the credential a form asks for. */
export const SetupGuideButton = ({
  guides,
  className,
}: SetupGuideButtonProps) => {
  const [open, setOpen] = useState(false);

  if (guides.length === 0) return null;

  return (
    <>
      <Button
        type="button"
        variant="outline"
        size="sm"
        className={className}
        onClick={() => setOpen(true)}
      >
        <BookOpen aria-hidden="true" />
        {MODAL_TITLE}
      </Button>
      <Modal
        open={open}
        onOpenChange={setOpen}
        title={MODAL_TITLE}
        description="How to create this credential and connect it securely."
        size="2xl"
        scrollable
      >
        {open && <SetupGuideContent guides={guides} />}
      </Modal>
    </>
  );
};

interface ProviderSetupGuideButtonProps {
  /** Type picked in the wizard; falls back to the provider being edited. */
  providerType?: string | null;
  className?: string;
}

/** Guide for the provider and credential method chosen in the wizard. */
export const ProviderSetupGuideButton = ({
  providerType,
  className,
}: ProviderSetupGuideButtonProps) => {
  const storedProviderType = useProviderWizardStore(
    (state) => state.providerType,
  );
  const via = useProviderWizardStore((state) => state.via);
  // AWS picks its method in the connect step, before `via` is stored.
  const awsMethod = useProviderWizardStore(
    (state) => state.awsConnectDraft?.method,
  );

  return (
    <SetupGuideButton
      guides={getProviderSetupGuides(
        providerType ?? storedProviderType,
        via ?? awsMethod,
      )}
      className={className}
    />
  );
};

interface IntegrationSetupGuideButtonProps {
  integration: SetupGuideIntegration;
  className?: string;
}

export const IntegrationSetupGuideButton = ({
  integration,
  className,
}: IntegrationSetupGuideButtonProps) => (
  <SetupGuideButton
    guides={getIntegrationSetupGuides(integration)}
    className={className}
  />
);
