import { BRAND } from "@/cloudsneeker/brand";

/** CLI command users run before uploading; the product ships this entry point. */
export const CLI_IMPORT_COMMAND = `${BRAND.shortName.toLowerCase()} aws --output-formats json-ocsf`;

const STEPS = [
  {
    title: "Run a scan from the CLI",
    body: "Add the OCSF output format to any provider scan:",
    command: CLI_IMPORT_COMMAND,
  },
  {
    title: "Pick the report",
    body: "Choose the .ocsf.json file from the scan output folder.",
  },
  {
    title: "Start the import",
    body: "Findings show up in Scans and Findings once processing finishes. You can close this window while it runs.",
  },
] as const;

/** Numbered how-to shown above the upload area in the Import findings dialog. */
export const CliImportSteps = () => (
  <ol
    aria-label="How to import findings"
    data-slot="cli-import-steps"
    className="border-border-neutral-secondary bg-bg-neutral-tertiary flex flex-col gap-3 rounded-lg border p-4"
  >
    {STEPS.map((step, index) => (
      <li key={step.title} className="flex min-w-0 gap-3">
        <span
          aria-hidden="true"
          className="bg-button-tertiary/10 text-button-tertiary flex size-6 shrink-0 items-center justify-center rounded-full text-xs font-semibold"
        >
          {index + 1}
        </span>
        <div className="flex min-w-0 flex-col gap-1">
          <span className="text-text-neutral-primary text-sm font-medium">
            {step.title}
          </span>
          <span className="text-text-neutral-secondary text-xs">
            {step.body}
          </span>
          {"command" in step ? (
            <code className="bg-bg-neutral-secondary border-border-neutral-secondary text-text-neutral-primary block overflow-x-auto rounded-md border px-2 py-1 font-mono text-xs whitespace-nowrap">
              {step.command}
            </code>
          ) : null}
        </div>
      </li>
    ))}
  </ol>
);
