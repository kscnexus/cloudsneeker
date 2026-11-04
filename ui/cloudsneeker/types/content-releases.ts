// Types for `GET /content-releases` (EB-049). Keys match
// `cloudsneeker/tools/content_release_notes.py`.

export const CHANGE_KIND = {
  ADDED: "added",
  CHANGED: "changed",
  REMOVED: "removed",
} as const;

export type ChangeKind = (typeof CHANGE_KIND)[keyof typeof CHANGE_KIND];

export interface CheckChange {
  id: string;
  provider: string;
  service: string;
  title: string | null;
  severity: string | null;
  /** Changed metadata fields; only on changed checks. */
  fields?: string[];
}

export interface FrameworkChange {
  id: string;
  name: string;
  provider: string;
  version: string | null;
  requirements: number;
  /** Only on changed frameworks. */
  fields?: string[];
  requirements_added?: number;
  requirements_removed?: number;
  requirements_remapped?: number;
}

export type ChangeSet<T> = Record<ChangeKind, T[]>;

export interface ContentReleaseAttributes {
  version: string;
  /** The release the product ships; it follows upstream and has no date. */
  current: boolean;
  previous_version: string;
  released_at: string | null;
  summary: Record<string, number>;
  checks: ChangeSet<CheckChange>;
  frameworks: ChangeSet<FrameworkChange>;
}

export interface ContentReleaseResource {
  type: "cloudsneeker-content-releases";
  id: string;
  attributes: ContentReleaseAttributes;
}
