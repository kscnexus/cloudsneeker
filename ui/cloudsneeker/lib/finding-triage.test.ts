import { describe, expect, it } from "vitest";

import {
  findingIdOf,
  findingIdsNeedingTriage,
  mergeTriageLookup,
  parseTriagePage,
  parseTriageStatus,
  TRIAGE_LOOKUP_MAX_FINDINGS,
  TRIAGE_PAGE_SIZE,
  triageFindingsHref,
  triageListSearchParams,
  triagePageHref,
  triageStatusLabel,
} from "./finding-triage";

const lookup = {
  data: [
    {
      type: "cloudsneeker-finding-triage-lookups",
      id: "finding-1",
      attributes: {
        finding_id: "finding-1",
        finding_uid: "uid-1",
        triage_id: "triage-1",
        triage_status: "remediating",
        triage_notes_count: 2,
        triage_has_note: true,
        assignee_id: null,
      },
    },
  ],
};

describe("findingIdsNeedingTriage", () => {
  it("collects ids of rows without triage fields", () => {
    const response = {
      data: [
        { id: "finding-1", attributes: { uid: "uid-1" } },
        { id: "finding-1", attributes: { uid: "uid-1" } },
        { id: "finding-2", attributes: { triage_status: "open" } },
        { id: "resource-row", attributes: { finding_id: "finding-3" } },
        "not-a-resource",
      ],
    };

    expect(findingIdsNeedingTriage(response)).toEqual([
      "finding-1",
      "finding-3",
    ]);
  });

  it("reads a single resource and ignores errors and blanks", () => {
    expect(
      findingIdsNeedingTriage({ data: { id: "finding-9", attributes: {} } }),
    ).toEqual(["finding-9"]);
    expect(findingIdsNeedingTriage({ errors: [{ detail: "x" }] })).toEqual([]);
    expect(findingIdsNeedingTriage(undefined)).toEqual([]);
    expect(findingIdsNeedingTriage({ data: [{ id: "x" }] })).toEqual([]);
  });

  it("caps the lookup size", () => {
    const data = Array.from(
      { length: TRIAGE_LOOKUP_MAX_FINDINGS + 5 },
      (_, index) => ({ id: `finding-${index}`, attributes: {} }),
    );

    expect(findingIdsNeedingTriage({ data })).toHaveLength(
      TRIAGE_LOOKUP_MAX_FINDINGS,
    );
  });

  it("prefers attributes.finding_id over the row id", () => {
    expect(findingIdOf({ id: "row", attributes: { finding_id: "f" } })).toBe(
      "f",
    );
    expect(findingIdOf({ id: "row", attributes: {} })).toBe("row");
    expect(findingIdOf({ attributes: {} })).toBeNull();
  });
});

describe("mergeTriageLookup", () => {
  it("adds triage fields to matching list rows only", () => {
    const response = {
      data: [
        { id: "finding-1", attributes: { uid: "uid-1", status: "FAIL" } },
        { id: "finding-2", attributes: { uid: "uid-2", status: "FAIL" } },
      ],
      meta: { pagination: { count: 2 } },
    };

    const merged = mergeTriageLookup(response, lookup);

    expect(merged.data[0].attributes).toEqual({
      uid: "uid-1",
      status: "FAIL",
      finding_uid: "uid-1",
      triage_id: "triage-1",
      triage_status: "remediating",
      triage_notes_count: 2,
      triage_has_note: true,
    });
    expect(merged.data[1]).toBe(response.data[1]);
    expect(merged.meta).toBe(response.meta);
    expect(response.data[0].attributes).not.toHaveProperty("triage_status");
  });

  it("merges a single resource and keeps rows that already have triage", () => {
    const single = { data: { id: "finding-1", attributes: {} } };
    expect(mergeTriageLookup(single, lookup).data.attributes).toMatchObject({
      triage_status: "remediating",
    });

    const cloud = {
      data: [{ id: "finding-1", attributes: { triage_status: "open" } }],
    };
    expect(mergeTriageLookup(cloud, lookup).data[0].attributes).toEqual({
      triage_status: "open",
    });
  });

  it("returns the response unchanged for an empty or failed lookup", () => {
    const response = { data: [{ id: "finding-1", attributes: {} }] };

    expect(mergeTriageLookup(response, { data: [] })).toBe(response);
    expect(mergeTriageLookup(response, { errors: [] })).toBe(response);
    expect(mergeTriageLookup(response, undefined)).toBe(response);
  });
});

describe("triage page helpers", () => {
  it("parses the status and page from the query", () => {
    expect(parseTriageStatus("false_positive")).toBe("false_positive");
    expect(parseTriageStatus(["resolved", "open"])).toBe("resolved");
    expect(parseTriageStatus("nope")).toBeNull();
    expect(parseTriageStatus(undefined)).toBeNull();
    expect(parseTriagePage("3")).toBe(3);
    expect(parseTriagePage("0")).toBe(1);
    expect(parseTriagePage("x")).toBe(1);
  });

  it("builds the API query", () => {
    expect(triageListSearchParams({ status: "resolved", page: 2 })).toEqual({
      "page[number]": "2",
      "page[size]": String(TRIAGE_PAGE_SIZE),
      sort: "-updated_at",
      "filter[status]": "resolved",
    });
    expect(
      triageListSearchParams({ status: null, page: 1 }),
    ).not.toHaveProperty("filter[status]");
  });

  it("builds page and findings links", () => {
    expect(triagePageHref(null)).toBe("/triage");
    expect(triagePageHref("under_review", 2)).toBe(
      "/triage?status=under_review&page=2",
    );
    expect(triageFindingsHref("s3_bucket_public")).toBe(
      "/findings?filter%5Bcheck_id__in%5D=s3_bucket_public",
    );
    expect(triageFindingsHref("")).toBe("/findings");
  });

  it("labels statuses", () => {
    expect(triageStatusLabel("risk_accepted")).toBe("Risk Accepted");
    expect(triageStatusLabel("custom")).toBe("custom");
  });
});
