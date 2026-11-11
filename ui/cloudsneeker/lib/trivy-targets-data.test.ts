import { beforeEach, describe, expect, it, vi } from "vitest";

const { listMock } = vi.hoisted(() => ({ listMock: vi.fn() }));

vi.mock("@/cloudsneeker/actions/trivy", () => ({
  listTrivyTargets: listMock,
}));

import { loadAllTargets, MAX_TARGET_PAGES } from "./trivy-targets-data";

const target = (id: string) => ({
  id,
  type: "cloudsneeker-trivy-targets",
  attributes: { name: id, mode: "repo", config: {}, provider_id: "p" },
});

const page = (ids: string[], pages: number) => ({
  data: ids.map(target),
  meta: { pagination: { pages } },
});

describe("loadAllTargets", () => {
  beforeEach(() => {
    listMock.mockReset();
  });

  it("reads every page, not just the first 100 targets", async () => {
    listMock.mockImplementation(
      async (params: Record<string, string>) =>
        ({
          "1": page(["a", "b"], 3),
          "2": page(["c", "d"], 3),
          "3": page(["e"], 3),
        })[params["page[number]"]],
    );

    const loaded = await loadAllTargets({ "filter[mode]": "repo" }, "name");

    expect(loaded?.targets.map((item) => item.id)).toEqual([
      "a",
      "b",
      "c",
      "d",
      "e",
    ]);
    expect(loaded?.truncated).toBe(false);
    expect(listMock).toHaveBeenCalledTimes(3);
    expect(listMock.mock.calls[0][0]).toEqual({
      "filter[mode]": "repo",
      "page[size]": "100",
      "page[number]": "1",
      sort: "name",
    });
  });

  it("returns null when the first page fails", async () => {
    listMock.mockResolvedValue({ error: "down" });
    expect(await loadAllTargets()).toBeNull();
  });

  it("marks the list truncated when a later page fails", async () => {
    listMock
      .mockResolvedValueOnce(page(["a"], 2))
      .mockResolvedValueOnce({ error: "down" });
    const loaded = await loadAllTargets();
    expect(loaded).toEqual({ targets: [expect.anything()], truncated: true });
  });

  it("stops at the page limit", async () => {
    listMock.mockResolvedValue(page(["a"], MAX_TARGET_PAGES + 5));
    const loaded = await loadAllTargets();
    expect(listMock).toHaveBeenCalledTimes(MAX_TARGET_PAGES);
    expect(loaded?.truncated).toBe(true);
  });
});
