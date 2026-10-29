import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  RunStatusBadge,
  runStatusLabel,
  runStatusVariant,
} from "./run-status-badge";

describe("RunStatusBadge", () => {
  it("maps run statuses to labels and badge variants", () => {
    expect(runStatusLabel("pending")).toBe("Queued");
    expect(runStatusLabel("cancelled")).toBe("Cancelled");
    expect(runStatusLabel("")).toBe("Unknown");
    expect(runStatusVariant("completed")).toBe("success");
    expect(runStatusVariant("failed")).toBe("error");
    expect(runStatusVariant("other")).toBe("tag");
  });

  it("renders the label", () => {
    render(<RunStatusBadge status="running" />);

    expect(screen.getByText("Running")).toBeInTheDocument();
  });
});
