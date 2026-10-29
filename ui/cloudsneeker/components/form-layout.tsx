import type { ReactNode } from "react";

import { Label } from "@/components/shadcn";
import { cn } from "@/lib/utils";

// Building blocks shared by the Cloudsneeker create/edit forms, so labels,
// help text, field errors, the form-level error and the submit row look the
// same on every page. Sections use `SectionCard`.

export const fieldHelpId = (id: string) => `${id}-help`;
export const fieldErrorId = (id: string) => `${id}-error`;

/** `aria-describedby` for a control rendered inside `FormField`. */
export const fieldDescribedBy = (
  id: string,
  { help, error }: { help?: boolean; error?: string },
): string | undefined => {
  const ids = [help ? fieldHelpId(id) : null, error ? fieldErrorId(id) : null]
    .filter((value): value is string => Boolean(value))
    .join(" ");
  return ids || undefined;
};

interface FieldErrorProps {
  id?: string;
  message?: string;
}

export const FieldError = ({ id, message }: FieldErrorProps) =>
  message ? (
    <p
      id={id}
      role="alert"
      data-slot="field-error"
      className="text-text-error-primary text-xs"
    >
      {message}
    </p>
  ) : null;

interface FormFieldProps {
  /** Id of the control; the label points at it. */
  id: string;
  label: ReactNode;
  help?: ReactNode;
  error?: string;
  optional?: boolean;
  children: ReactNode;
  className?: string;
}

export const FormField = ({
  id,
  label,
  help,
  error,
  optional = false,
  children,
  className,
}: FormFieldProps) => (
  <div
    data-slot="form-field"
    className={cn("flex min-w-0 flex-col gap-1.5", className)}
  >
    <Label htmlFor={id} className="text-text-neutral-primary">
      {label}
      {optional ? (
        <span className="text-text-neutral-tertiary ml-1 font-normal">
          (optional)
        </span>
      ) : null}
    </Label>
    {children}
    {help ? (
      <p id={fieldHelpId(id)} className="text-text-neutral-tertiary text-xs">
        {help}
      </p>
    ) : null}
    <FieldError id={fieldErrorId(id)} message={error} />
  </div>
);

interface FormChoiceGroupProps {
  legend: string;
  help?: ReactNode;
  error?: string;
  children: ReactNode;
  className?: string;
}

/** A set of checkboxes or radios with one label. */
export const FormChoiceGroup = ({
  legend,
  help,
  error,
  children,
  className,
}: FormChoiceGroupProps) => (
  <fieldset
    data-slot="form-choice-group"
    className={cn("flex min-w-0 flex-col gap-2", className)}
  >
    <legend className="text-text-neutral-primary mb-1 text-sm font-medium">
      {legend}
    </legend>
    {children}
    {help ? <p className="text-text-neutral-tertiary text-xs">{help}</p> : null}
    <FieldError message={error} />
  </fieldset>
);

/** Error returned by the save call, shown above the submit row. */
export const FormAlert = ({ message }: { message?: string | null }) =>
  message ? (
    <div
      role="alert"
      data-slot="form-alert"
      className="border-border-error bg-bg-fail-secondary text-text-error-primary rounded-lg border px-4 py-3 text-sm break-words"
    >
      {message}
    </div>
  ) : null;

interface FormActionsProps {
  /** Put the cancel control first and the submit control last. */
  children: ReactNode;
  className?: string;
}

/**
 * Submit row. On phones the buttons stack full width with the submit on top;
 * from `sm` they sit on one line, aligned right.
 */
export const FormActions = ({ children, className }: FormActionsProps) => (
  <div
    data-slot="form-actions"
    className={cn(
      "border-border-neutral-secondary flex flex-col-reverse gap-2 border-t pt-4 sm:flex-row sm:items-center sm:justify-end [&>*]:w-full sm:[&>*]:w-auto",
      className,
    )}
  >
    {children}
  </div>
);
