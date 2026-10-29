// Class strings shared by the Cloudsneeker page components. Kept in one
// place so focus rings and lists read the same on every page.

/** Visible keyboard focus for links and cards that act as links. */
export const FOCUS_RING_CLASS =
  "outline-none focus-visible:ring-2 focus-visible:ring-button-tertiary focus-visible:ring-offset-2 focus-visible:ring-offset-bg-neutral-primary";

/** Divided list rendered inside a section card. */
export const CARD_LIST_CLASS =
  "divide-border-neutral-secondary border-border-neutral-secondary divide-y rounded-lg border";

/** Native `<select>` styled like the shadcn input, with the same focus ring. */
export const FORM_SELECT_CLASS =
  "border-border-input-primary bg-bg-input-primary text-text-neutral-primary h-10 w-full min-w-0 rounded-md border px-3 text-sm outline-none focus-visible:border-border-input-primary-pressed focus-visible:ring-2 focus-visible:ring-button-tertiary/30 disabled:cursor-not-allowed disabled:opacity-60";

/** Native checkbox or radio input. */
export const FORM_CHECK_CLASS = "accent-button-tertiary size-4 shrink-0";

/** Label that wraps a checkbox or radio and its text. */
export const FORM_CHOICE_CLASS =
  "text-text-neutral-primary flex min-w-0 items-start gap-2 text-sm [&>input]:mt-0.5";

/** Outer layout of a create/edit form: one column, sections stacked. */
export const FORM_CLASS = "flex w-full max-w-3xl min-w-0 flex-col gap-6";

/**
 * Marks an upstream page whose tables and dialogs take the Cloudsneeker look
 * from `ui/cloudsneeker/styles/ops-surfaces.css`. The attribute sits on the
 * Cloudsneeker summary rendered first on the page, so the upstream markup is
 * not edited.
 */
export const CLOUDSNEEKER_SURFACE = {
  ALERTS: "alerts",
  SCAN_PROFILES: "scan-profiles",
} as const;

export type CloudsneekerSurface =
  (typeof CLOUDSNEEKER_SURFACE)[keyof typeof CLOUDSNEEKER_SURFACE];
