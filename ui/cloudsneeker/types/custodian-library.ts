export const LIBRARY_PROVIDER = {
  AWS: "aws",
  AZURE: "azure",
  GCP: "gcp",
} as const;

export type LibraryProvider =
  (typeof LIBRARY_PROVIDER)[keyof typeof LIBRARY_PROVIDER];

export const LIBRARY_SEVERITY = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
} as const;

export type LibrarySeverity =
  (typeof LIBRARY_SEVERITY)[keyof typeof LIBRARY_SEVERITY];

export interface LibraryPolicyAttributes {
  id: string;
  name: string;
  description: string;
  provider_type: LibraryProvider;
  category: string;
  category_name: string;
  severity: LibrarySeverity;
  resource: string;
  frameworks: string[];
  starter: boolean;
  policy_yaml: string;
  installed: boolean;
}

export interface LibraryPolicyResource {
  id: string;
  type: string;
  attributes: LibraryPolicyAttributes;
}

export interface LibraryCategory {
  id: string;
  name: string;
  description: string;
}

export interface LibraryCoverageRow {
  provider_type: LibraryProvider;
  category: string;
  category_name: string;
  total: number;
  active: number;
}

export interface LibraryListResponse {
  data: LibraryPolicyResource[];
  meta: {
    count: number;
    categories: LibraryCategory[];
    coverage: LibraryCoverageRow[];
  };
}

export interface PolicyDraftAttributes {
  policy_yaml: string;
  name: string;
  description: string;
  resource: string;
  provider_type: LibraryProvider;
  valid: boolean;
  validation_error: string;
  attempts: number;
}

export interface PolicyValidationAttributes {
  valid: boolean;
  error: string;
}
