import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  fieldDescribedBy,
  FormActions,
  FormAlert,
  FormChoiceGroup,
  FormField,
} from "./form-layout";

describe("FormField", () => {
  it("labels the control and shows help, optional marker and error", () => {
    render(
      <FormField
        id="target-name"
        label="Name"
        help="Shown in lists."
        error="Name is required."
        optional
      >
        <input id="target-name" />
      </FormField>,
    );

    expect(screen.getByLabelText(/Name/)).toHaveAttribute("id", "target-name");
    expect(screen.getByText("(optional)")).toBeInTheDocument();
    expect(screen.getByText("Shown in lists.")).toHaveAttribute(
      "id",
      "target-name-help",
    );
    expect(screen.getByRole("alert")).toHaveTextContent("Name is required.");
  });

  it("renders no error region without an error", () => {
    render(
      <FormField id="cron" label="Cron">
        <input id="cron" />
      </FormField>,
    );

    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("fieldDescribedBy", () => {
  it("joins the help and error ids that are present", () => {
    expect(fieldDescribedBy("a", { help: true, error: "Bad" })).toBe(
      "a-help a-error",
    );
    expect(fieldDescribedBy("a", { help: true })).toBe("a-help");
    expect(fieldDescribedBy("a", {})).toBeUndefined();
  });
});

describe("FormChoiceGroup", () => {
  it("is a named group with its error", () => {
    render(
      <FormChoiceGroup legend="Rule packs" error="Pick at least one.">
        <label>
          <input type="checkbox" /> Auto
        </label>
      </FormChoiceGroup>,
    );

    expect(
      screen.getByRole("group", { name: "Rule packs" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("Pick at least one.");
  });
});

describe("FormAlert", () => {
  it("announces a save error and renders nothing without one", () => {
    const { rerender } = render(<FormAlert message="Failed to save target." />);
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Failed to save target.",
    );

    rerender(<FormAlert message={null} />);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("FormActions", () => {
  it("stacks buttons on phones and right-aligns them from sm", () => {
    render(
      <FormActions>
        <button type="button">Cancel</button>
        <button type="submit">Save</button>
      </FormActions>,
    );

    const row = screen.getByRole("button", { name: "Save" }).parentElement;
    expect(row).toHaveAttribute("data-slot", "form-actions");
    expect(row?.className).toContain("flex-col-reverse");
    expect(row?.className).toContain("sm:justify-end");
  });
});
