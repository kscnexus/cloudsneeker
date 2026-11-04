import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { ContentReleaseAttributes } from "@/cloudsneeker/types/content-releases";

import {
  ContentReleasesPanel,
  formatReleaseDate,
  frameworkChangeSummary,
  providerLabel,
} from "./content-releases-panel";

const empty = { added: [], changed: [], removed: [] };

const releases: ContentReleaseAttributes[] = [
  {
    version: "5.45.0",
    current: true,
    previous_version: "5.44.0",
    released_at: null,
    summary: {},
    checks: empty,
    frameworks: empty,
  },
  {
    version: "5.43.0",
    current: false,
    previous_version: "5.42.0",
    released_at: "2026-09-15T10:00:00+02:00",
    summary: {},
    checks: {
      added: [
        {
          id: "s3_bucket_example",
          provider: "aws",
          service: "s3",
          title: "S3 bucket blocks public access",
          severity: "high",
        },
      ],
      changed: [
        {
          id: "iam_root_mfa",
          provider: "aws",
          service: "iam",
          title: "Root account has MFA",
          severity: "critical",
          fields: ["severity"],
        },
      ],
      removed: [],
    },
    frameworks: {
      added: [],
      changed: [],
      removed: [
        {
          id: "aws/fedramp_low",
          name: "FedRAMP Low",
          provider: "aws",
          version: "25.05C",
          requirements: 11,
        },
      ],
    },
  },
];

describe("ContentReleasesPanel", () => {
  it("lists each release with its changes", () => {
    render(<ContentReleasesPanel releases={releases} />);
    expect(screen.getByText("Release 5.45.0")).toBeInTheDocument();
    expect(
      screen.getByText("Running now · Compared with 5.44.0"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "No checks or compliance frameworks changed in this release.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Released 2026-09-15 · Compared with 5.42.0"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("S3 bucket blocks public access"),
    ).toBeInTheDocument();
    expect(screen.getByText("Updated: severity")).toBeInTheDocument();
    expect(screen.getByText("FedRAMP Low")).toBeInTheDocument();
  });
});

describe("helpers", () => {
  it("formats release dates in UTC", () => {
    expect(formatReleaseDate("2026-10-15T12:04:24+02:00")).toBe("2026-10-15");
    expect(formatReleaseDate(null)).toBeNull();
    expect(formatReleaseDate("not a date")).toBeNull();
  });

  it("names providers", () => {
    expect(providerLabel("multi-cloud")).toBe("Multi-cloud");
    expect(providerLabel("aws")).toBe("AWS");
  });

  it("summarizes framework changes", () => {
    expect(
      frameworkChangeSummary({
        id: "aws/cis",
        name: "CIS",
        provider: "aws",
        version: "3.0",
        requirements: 62,
        fields: ["version"],
        requirements_added: 1,
        requirements_removed: 0,
        requirements_remapped: 4,
      }),
    ).toBe(
      "1 requirement added, 4 requirements remapped to different checks, version updated",
    );
  });
});
