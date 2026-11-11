import { describe, expect, it } from "vitest";

import {
  APPSEC_DOWNLOAD_ERROR,
  buildAppSecDownloadHeaders,
  resolveAppSecDownload,
} from "./appsec-download";

const ID = "0b0e6a8e-0a57-4c8e-9f0b-6f0f7b2f3c11";
const resolve = (query: string) =>
  resolveAppSecDownload(new URLSearchParams(query));

describe("resolveAppSecDownload", () => {
  it("maps an SBOM download", () => {
    expect(resolve(`kind=sbom&format=cyclonedx&id=${ID}`)).toEqual({
      path: `/appsec-sboms/${ID}/download?format=cyclonedx`,
      fallbackName: `sbom-${ID}.cyclonedx.json`,
    });
  });

  it("maps a scan report export with an index", () => {
    expect(resolve(`kind=scan&format=sarif&id=${ID}&index=2`)).toEqual({
      path: `/trivy-runs/${ID}/export?format=sarif&index=2`,
      fallbackName: `scan-${ID}.sarif.json`,
    });
    const plain = resolve(`kind=scan&format=json&id=${ID}&index=abc`);
    expect(plain).toMatchObject({
      path: `/trivy-runs/${ID}/export?format=json`,
    });
  });

  it("keeps only finding filters on a findings export", () => {
    const target = resolve(
      "kind=findings&format=csv&filter%5Bcategory%5D=secret&sort=-priority&page%5Bsize%5D=1&evil=1",
    );
    expect(target).toEqual({
      path: "/appsec-findings/export?format=csv&filter%5Bcategory%5D=secret&sort=-priority",
      fallbackName: "findings.csv",
    });
  });

  it("rejects anything else", () => {
    expect(resolve("kind=secrets&format=csv")).toBe(APPSEC_DOWNLOAD_ERROR.KIND);
    expect(resolve(`kind=sbom&format=pdf&id=${ID}`)).toBe(
      APPSEC_DOWNLOAD_ERROR.FORMAT,
    );
    expect(resolve("kind=sbom&format=cyclonedx&id=../../users")).toBe(
      APPSEC_DOWNLOAD_ERROR.ID,
    );
    expect(resolve("kind=scan&format=json")).toBe(APPSEC_DOWNLOAD_ERROR.ID);
  });
});

describe("buildAppSecDownloadHeaders", () => {
  it("copies file headers and never caches", () => {
    const headers = buildAppSecDownloadHeaders(
      new Headers({
        "content-type": "text/csv",
        "content-disposition": 'attachment; filename="x.csv"',
        "set-cookie": "a=b",
      }),
      "fallback.csv",
    );
    expect(headers.get("content-type")).toBe("text/csv");
    expect(headers.get("content-disposition")).toContain("x.csv");
    expect(headers.get("cache-control")).toBe("no-store");
    expect(headers.get("set-cookie")).toBeNull();
  });

  it("falls back to a file name", () => {
    const headers = buildAppSecDownloadHeaders(new Headers(), "sbom.json");
    expect(headers.get("content-disposition")).toBe(
      'attachment; filename="sbom.json"',
    );
  });
});
