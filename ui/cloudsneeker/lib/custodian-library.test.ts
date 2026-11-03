import { describe, expect, it } from "vitest";

import type {
  LibraryCoverageRow,
  LibraryPolicyAttributes,
} from "@/cloudsneeker/types/custodian-library";

import {
  actionError,
  coveragePercent,
  draftName,
  EMPTY_LIBRARY_FILTERS,
  filterLibraryPolicies,
  installMessage,
  libraryHref,
  libraryProviderFromParam,
  pendingStarterIds,
  GENERATE_EXAMPLES,
  readDraft,
  readInstallResult,
  readValidation,
  summarizeCoverage,
} from "./custodian-library";

const policy = (
  overrides: Partial<LibraryPolicyAttributes>,
): LibraryPolicyAttributes => ({
  id: "aws-x",
  name: "Policy",
  description: "Finds things.",
  provider_type: "aws",
  category: "network",
  category_name: "Network",
  severity: "medium",
  resource: "aws.security-group",
  frameworks: ["CIS"],
  starter: false,
  policy_yaml: "policies: []\n",
  installed: false,
  ...overrides,
});

const POLICIES = [
  policy({ id: "a", name: "SSH open", severity: "high", starter: true }),
  policy({
    id: "b",
    name: "Unencrypted volumes",
    category: "encryption",
    category_name: "Encryption & data protection",
    severity: "critical",
    resource: "aws.ebs",
    frameworks: ["PCI DSS"],
    installed: true,
    starter: true,
  }),
  policy({ id: "c", name: "Idle VMs", category: "cost", severity: "low" }),
];

describe("filterLibraryPolicies", () => {
  it("sorts by severity then name with no filters", () => {
    expect(
      filterLibraryPolicies(POLICIES, EMPTY_LIBRARY_FILTERS).map((p) => p.id),
    ).toEqual(["b", "a", "c"]);
  });

  it("matches every search term across name, resource and frameworks", () => {
    const ids = (search: string) =>
      filterLibraryPolicies(POLICIES, { ...EMPTY_LIBRARY_FILTERS, search }).map(
        (p) => p.id,
      );
    expect(ids("ssh")).toEqual(["a"]);
    expect(ids("aws.ebs pci")).toEqual(["b"]);
    expect(ids("ssh pci")).toEqual([]);
  });

  it("filters by category, severity, starter and installed", () => {
    const run = (extra: Partial<typeof EMPTY_LIBRARY_FILTERS>) =>
      filterLibraryPolicies(POLICIES, {
        ...EMPTY_LIBRARY_FILTERS,
        ...extra,
      }).map((p) => p.id);
    expect(run({ category: "cost" })).toEqual(["c"]);
    expect(run({ severity: "high" })).toEqual(["a"]);
    expect(run({ starterOnly: true })).toEqual(["b", "a"]);
    expect(run({ hideInstalled: true })).toEqual(["a", "c"]);
  });
});

describe("starter pack and coverage", () => {
  it("lists starter policies not yet installed", () => {
    expect(pendingStarterIds(POLICIES)).toEqual(["a"]);
  });

  it("summarises coverage for one provider", () => {
    const rows: LibraryCoverageRow[] = [
      {
        provider_type: "aws",
        category: "network",
        category_name: "Network",
        total: 10,
        active: 2,
      },
      {
        provider_type: "aws",
        category: "cost",
        category_name: "Cost",
        total: 5,
        active: 0,
      },
      {
        provider_type: "gcp",
        category: "network",
        category_name: "Network",
        total: 8,
        active: 8,
      },
    ];
    expect(summarizeCoverage(rows, "aws")).toMatchObject({
      active: 2,
      total: 15,
      coveredCategories: 1,
    });
    expect(summarizeCoverage(rows, "azure").total).toBe(0);
    expect(coveragePercent(2, 15)).toBe(13);
    expect(coveragePercent(0, 0)).toBe(0);
  });
});

describe("routing helpers", () => {
  it("defaults unknown providers to AWS", () => {
    expect(libraryProviderFromParam("gcp")).toBe("gcp");
    expect(libraryProviderFromParam(["azure"])).toBe("azure");
    expect(libraryProviderFromParam("kubernetes")).toBe("aws");
    expect(libraryProviderFromParam(undefined)).toBe("aws");
  });

  it("builds library links without engine names", () => {
    expect(libraryHref()).toBe("/governance/library");
    expect(libraryHref("azure")).toBe("/governance/library?provider=azure");
  });
});

describe("install results", () => {
  it("reads counts from the response meta", () => {
    expect(readInstallResult({ meta: { created: 2, skipped: ["x"] } })).toEqual(
      {
        created: 2,
        skipped: ["x"],
      },
    );
    expect(readInstallResult({ error: "nope" })).toBeNull();
    expect(readInstallResult(undefined)).toBeNull();
  });

  it("describes what happened", () => {
    expect(installMessage({ created: 1, skipped: [] })).toBe("Added 1 policy.");
    expect(installMessage({ created: 3, skipped: ["a"] })).toBe(
      "Added 3 policies. 1 was already on this provider.",
    );
    expect(installMessage({ created: 0, skipped: ["a", "b"] })).toBe(
      "Nothing added: 2 were already on this provider.",
    );
  });

  it("extracts action errors", () => {
    expect(actionError({ error: "Bad request" })).toBe("Bad request");
    expect(actionError({ data: [] })).toBeNull();
    expect(actionError(undefined)).toBe("Something went wrong. Try again.");
  });
});

describe("AI drafts", () => {
  it("reads draft and validation attributes", () => {
    const draft = readDraft({
      data: { attributes: { policy_yaml: "policies: []\n", valid: true } },
    });
    expect(draft?.policy_yaml).toBe("policies: []\n");
    expect(readDraft({ error: "Seeker AI is not set up." })).toBeNull();
    expect(
      readValidation({ data: { attributes: { valid: false, error: "bad" } } }),
    ).toEqual({ valid: false, error: "bad" });
    expect(readValidation({ data: {} })).toBeNull();
  });

  it("turns the draft slug into a readable name", () => {
    expect(draftName("unencrypted-ebs-volumes", "x")).toBe(
      "Unencrypted ebs volumes",
    );
    expect(draftName("", "public buckets")).toBe("Public buckets");
    expect(draftName("", "  ")).toBe("");
    expect(draftName("a".repeat(150), "").length).toBe(100);
  });

  it("offers examples for every cloud", () => {
    for (const examples of Object.values(GENERATE_EXAMPLES)) {
      expect(examples.length).toBeGreaterThan(0);
      for (const example of examples) {
        expect(example.length).toBeGreaterThanOrEqual(10);
      }
    }
  });
});
