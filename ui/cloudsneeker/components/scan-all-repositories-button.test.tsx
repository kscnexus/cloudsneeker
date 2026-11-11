import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { planMock, batchMock, refreshMock } = vi.hoisted(() => ({
  planMock: vi.fn(),
  batchMock: vi.fn(),
  refreshMock: vi.fn(),
}));

vi.mock("@/cloudsneeker/actions/app-security-scan-all", () => ({
  planScanAllRepositories: planMock,
  scanRepositoryBatch: batchMock,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: refreshMock }),
}));

import { ScanAllRepositoriesButton } from "./scan-all-repositories-button";

const item = (
  index: number,
  targetId?: string,
  mode: "repo" | "sast" = "repo",
) => ({
  providerId: `p${index}`,
  repositoryUrl: `git@bitbucket.org:acme/r${index}.git`,
  name: `acme/r${index}`,
  mode,
  ...(targetId ? { targetId } : {}),
});

describe("ScanAllRepositoriesButton", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("asks before starting and says how many targets it creates", async () => {
    planMock.mockResolvedValue({
      items: [
        item(1, "t1"),
        item(1, undefined, "sast"),
        item(2),
        item(2, undefined, "sast"),
      ],
    });
    const user = userEvent.setup();
    render(<ScanAllRepositoriesButton />);

    await user.click(
      screen.getByRole("button", { name: "Scan all repositories" }),
    );

    expect(
      await screen.findByText(/start 4 scans on 2 repositories/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/static analysis scan/i)).toBeInTheDocument();
    expect(screen.getByText(/3 targets will be created/i)).toBeInTheDocument();
    expect(batchMock).not.toHaveBeenCalled();
  });

  it("starts scans in batches of 10 and reports failures", async () => {
    const items = Array.from({ length: 12 }, (_, index) => item(index));
    planMock.mockResolvedValue({ items });
    batchMock.mockImplementation(async (batch: typeof items) =>
      batch.map((entry) => ({
        providerId: entry.providerId,
        name: entry.name,
        started: entry.providerId !== "p11",
        ...(entry.providerId === "p11" ? { message: "No access" } : {}),
      })),
    );
    const user = userEvent.setup();
    render(<ScanAllRepositoriesButton />);

    await user.click(
      screen.getByRole("button", { name: "Scan all repositories" }),
    );
    await user.click(
      await screen.findByRole("button", { name: "Start 12 scans" }),
    );

    await waitFor(() =>
      expect(screen.getByText(/11 scans started/i)).toBeInTheDocument(),
    );
    expect(batchMock).toHaveBeenCalledTimes(2);
    expect(batchMock.mock.calls[0][0]).toHaveLength(10);
    expect(screen.getByText("acme/r11")).toBeInTheDocument();
    expect(screen.getByText("No access")).toBeInTheDocument();
    expect(refreshMock).toHaveBeenCalled();
  });

  it("explains when there are no connected repositories", async () => {
    planMock.mockResolvedValue({ items: [] });
    const user = userEvent.setup();
    render(<ScanAllRepositoriesButton />);

    await user.click(
      screen.getByRole("button", { name: "Scan all repositories" }),
    );

    expect(
      await screen.findByText(/no connected repositories/i),
    ).toBeInTheDocument();
  });

  it("shows the error when the repositories cannot be loaded", async () => {
    planMock.mockResolvedValue({ error: "Service unavailable" });
    const user = userEvent.setup();
    render(<ScanAllRepositoriesButton />);

    await user.click(
      screen.getByRole("button", { name: "Scan all repositories" }),
    );

    expect(await screen.findByText("Service unavailable")).toBeInTheDocument();
  });
});
