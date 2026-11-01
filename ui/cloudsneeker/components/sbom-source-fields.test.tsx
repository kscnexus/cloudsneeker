import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SbomSourceFields } from "./sbom-source-fields";

const { generateMock } = vi.hoisted(() => ({ generateMock: vi.fn() }));

vi.mock("@/cloudsneeker/actions/sbom", () => ({
  generateSbomFromDescription: generateMock,
}));

const Harness = () => {
  const [sbom, setSbom] = useState("");
  return <SbomSourceFields value={sbom} onChange={setSbom} />;
};

const sbomField = () =>
  screen.getByLabelText("SBOM content") as HTMLTextAreaElement;

describe("SbomSourceFields", () => {
  beforeEach(() => generateMock.mockReset());

  it("converts an uploaded package.json into a CycloneDX SBOM", async () => {
    const user = userEvent.setup();
    render(<Harness />);

    const file = new File(
      [
        JSON.stringify({
          dependencies: { lodash: "^4.17.20", next: "latest" },
        }),
      ],
      "package.json",
      { type: "application/json" },
    );
    await user.upload(screen.getByLabelText(/Upload a file/), file);
    await screen.findByRole("status");

    const sbom = JSON.parse(sbomField().value);
    expect(sbom.components.map((item: { purl: string }) => item.purl)).toEqual([
      "pkg:npm/lodash@4.17.20",
    ]);
    expect(screen.getByRole("status")).toHaveTextContent(
      "package.json: Added 1 component. Skipped without an exact version: next.",
    );
  });

  it("keeps an uploaded SBOM document as is", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const document = '{"bomFormat":"CycloneDX","specVersion":"1.5"}';

    await user.upload(
      screen.getByLabelText(/Upload a file/),
      new File([document], "bom.json"),
    );

    await waitFor(() => expect(sbomField()).toHaveValue(document));
  });

  it("rejects files it cannot read", async () => {
    const user = userEvent.setup({ applyAccept: false });
    render(<Harness />);

    await user.upload(
      screen.getByLabelText(/Upload a file/),
      new File(["<project/>"], "pom.xml"),
    );

    expect(
      await screen.findByText(/Upload a CycloneDX or SPDX document/),
    ).toBeInTheDocument();
    expect(sbomField()).toHaveValue("");
  });

  it("fills the SBOM from a plain-language description", async () => {
    const user = userEvent.setup();
    generateMock.mockResolvedValue({
      sbom: '{"bomFormat":"CycloneDX"}',
      components: [{ name: "lodash", version: "4.17.20", ecosystem: "npm" }],
      skipped: [],
    });
    render(<Harness />);

    const generate = screen.getByRole("button", {
      name: "Generate with Seeker AI",
    });
    expect(generate).toBeDisabled();
    await user.type(
      screen.getByLabelText(/Describe your components/),
      "lodash 4.17.20",
    );
    await user.click(generate);

    expect(generateMock).toHaveBeenCalledWith("lodash 4.17.20");
    expect(sbomField()).toHaveValue('{"bomFormat":"CycloneDX"}');
    expect(screen.getByRole("status")).toHaveTextContent(
      "Added 1 component. Review the SBOM before saving.",
    );
  });

  it("shows the reason generation failed", async () => {
    const user = userEvent.setup();
    generateMock.mockResolvedValue({ error: "Seeker AI is not set up." });
    render(<Harness />);

    await user.type(screen.getByLabelText(/Describe your components/), "x 1");
    await user.click(
      screen.getByRole("button", { name: "Generate with Seeker AI" }),
    );

    expect(screen.getByText("Seeker AI is not set up.")).toBeInTheDocument();
    expect(sbomField()).toHaveValue("");
  });
});
