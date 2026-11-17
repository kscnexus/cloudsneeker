import type { Ref, SelectHTMLAttributes } from "react";

import {
  groupSourceOptions,
  type SourceConnectionOption,
  type SourceOption,
} from "@/cloudsneeker/lib/source-options";
import { FORM_SELECT_CLASS } from "@/cloudsneeker/lib/ui-classes";

interface SourcePickerProps extends SelectHTMLAttributes<HTMLSelectElement> {
  sources: SourceOption[];
  /** GitHub connections: their repositories are listed under them. */
  connections?: SourceConnectionOption[];
  /** Shown when there is nothing to pick. */
  emptyLabel?: string;
  /** Lets `react-hook-form`'s `register` attach its ref. */
  ref?: Ref<HTMLSelectElement>;
}

/**
 * The one source (provider) picker of every create form: repositories are
 * grouped under the GitHub connection they came from, the rest by type.
 */
export const SourcePicker = ({
  sources,
  connections = [],
  emptyLabel = "No matching sources",
  className,
  ...props
}: SourcePickerProps) => {
  const groups = groupSourceOptions(sources, connections);
  return (
    <select className={className ?? FORM_SELECT_CLASS} {...props}>
      {sources.length === 0 ? <option value="">{emptyLabel}</option> : null}
      {groups.length === 1
        ? groups[0].options.map((option) => (
            <option key={option.id} value={option.id}>
              {option.label}
            </option>
          ))
        : groups.map((group) => (
            <optgroup key={group.label} label={group.label}>
              {group.options.map((option) => (
                <option key={option.id} value={option.id}>
                  {option.label}
                </option>
              ))}
            </optgroup>
          ))}
    </select>
  );
};
