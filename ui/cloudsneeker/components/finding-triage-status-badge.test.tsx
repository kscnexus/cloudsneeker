import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  FindingTriageStatusBadge,
  triageStatusVariant,
} from "./finding-triage-status-badge";

describe("FindingTriageStatusBadge", () => {
  it("maps statuses to badge variants", () => {
    expect(triageStatusVariant("open")).toBe("error");
    expect(triageStatusVariant("reopened")).toBe("error");
    expect(triageStatusVariant("under_review")).toBe("warning");
    expect(triageStatusVariant("remediating")).toBe("info");
    expect(triageStatusVariant("resolved")).toBe("success");
    expect(triageStatusVariant("false_positive")).toBe("tag");
    expect(triageStatusVariant("other")).toBe("tag");
  });

  it("renders the label", () => {
    render(<FindingTriageStatusBadge status="false_positive" />);

    expect(screen.getByText("False Positive")).toBeInTheDocument();
  });
});
