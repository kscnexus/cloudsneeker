import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { CLI_IMPORT_COMMAND, CliImportSteps } from "./cli-import-steps";

describe("CliImportSteps", () => {
  it("lists the three import steps with the CLI command", () => {
    render(<CliImportSteps />);

    const list = screen.getByRole("list", { name: "How to import findings" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(3);
    expect(within(list).getByText(CLI_IMPORT_COMMAND)).toBeInTheDocument();
    expect(CLI_IMPORT_COMMAND).toContain("--output-formats json-ocsf");
  });

  it("names only the product CLI", () => {
    render(<CliImportSteps />);

    expect(document.body.textContent ?? "").not.toMatch(/prowler/i);
  });
});
