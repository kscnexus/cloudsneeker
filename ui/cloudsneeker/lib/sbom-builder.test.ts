import { describe, expect, it } from "vitest";

import {
  buildCycloneDxSbom,
  exactVersion,
  extractJsonObject,
  isSbomDocument,
  parseManifest,
  purlFor,
  sanitizeComponents,
} from "@/cloudsneeker/lib/sbom-builder";

describe("purlFor", () => {
  it.each([
    [
      { name: "lodash", version: "4.17.20", ecosystem: "npm" },
      "pkg:npm/lodash@4.17.20",
    ],
    [
      { name: "@babel/core", version: "7.0.0", ecosystem: "npm" },
      "pkg:npm/%40babel/core@7.0.0",
    ],
    [
      { name: "Django_Rest", version: "3.2", ecosystem: "pypi" },
      "pkg:pypi/django-rest@3.2",
    ],
    [
      {
        name: "org.apache.logging.log4j:log4j-core",
        version: "2.14.1",
        ecosystem: "maven",
      },
      "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    ],
    [
      { name: "golang.org/x/net", version: "v0.1.0", ecosystem: "golang" },
      "pkg:golang/golang.org/x/net@v0.1.0",
    ],
  ] as const)("%j → %s", (component, purl) => {
    expect(purlFor(component)).toBe(purl);
  });
});

describe("exactVersion", () => {
  it("strips range operators and rejects ranges without a version", () => {
    expect(exactVersion("^4.17.20")).toBe("4.17.20");
    expect(exactVersion("~1.2.3")).toBe("1.2.3");
    expect(exactVersion(">=2.0")).toBe("2.0");
    expect(exactVersion("latest")).toBeNull();
    expect(exactVersion("*")).toBeNull();
    expect(exactVersion(null)).toBeNull();
  });
});

describe("buildCycloneDxSbom", () => {
  it("writes a CycloneDX document the scanner can match by purl", () => {
    const sbom = JSON.parse(
      buildCycloneDxSbom(
        [
          { name: "lodash", version: "4.17.20", ecosystem: "npm" },
          { name: "lodash", version: "4.17.20", ecosystem: "npm" },
        ],
        new Date("2026-11-01T00:00:00Z"),
      ),
    );
    expect(sbom).toMatchObject({
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      metadata: { timestamp: "2026-11-01T00:00:00.000Z" },
    });
    expect(sbom.components).toEqual([
      {
        type: "library",
        "bom-ref": "pkg:npm/lodash@4.17.20",
        name: "lodash",
        version: "4.17.20",
        purl: "pkg:npm/lodash@4.17.20",
      },
    ]);
    expect(isSbomDocument(JSON.stringify(sbom))).toBe(true);
  });
});

describe("isSbomDocument", () => {
  it("recognizes CycloneDX and SPDX but not manifests", () => {
    expect(isSbomDocument('{"spdxVersion":"SPDX-2.3"}')).toBe(true);
    expect(
      isSbomDocument('<bom xmlns="http://cyclonedx.org/schema/bom/1.5">'),
    ).toBe(true);
    expect(isSbomDocument('{"name":"app","dependencies":{}}')).toBe(false);
    expect(isSbomDocument("not json")).toBe(false);
  });
});

describe("parseManifest", () => {
  it("reads pinned npm dependencies and skips unpinned ones", () => {
    const result = parseManifest(
      "web/package.json",
      JSON.stringify({
        dependencies: { react: "^17.0.2", next: "latest" },
        devDependencies: { vitest: "~4.1.0" },
      }),
    );
    expect(result).toEqual({
      components: [
        { name: "react", version: "17.0.2", ecosystem: "npm" },
        { name: "vitest", version: "4.1.0", ecosystem: "npm" },
      ],
      skipped: ["next"],
    });
  });

  it("reads pinned Python requirements", () => {
    const result = parseManifest(
      "requirements-prod.txt",
      "# api\nDjango==3.2.4\nrequests[socks]==2.25.1  # http\nflask>=2\n-r base.txt\n",
    );
    expect(result).toEqual({
      components: [
        { name: "Django", version: "3.2.4", ecosystem: "pypi" },
        { name: "requests", version: "2.25.1", ecosystem: "pypi" },
      ],
      skipped: ["flask"],
    });
  });

  it("reads go.mod requirements in and out of blocks", () => {
    const result = parseManifest(
      "go.mod",
      "module acme\n\nrequire github.com/gin-gonic/gin v1.7.0\n\nrequire (\n\tgolang.org/x/net v0.1.0 // indirect\n)\n",
    );
    expect(result?.components).toEqual([
      {
        name: "github.com/gin-gonic/gin",
        version: "v1.7.0",
        ecosystem: "golang",
      },
      { name: "golang.org/x/net", version: "v0.1.0", ecosystem: "golang" },
    ]);
  });

  it("returns null for files it does not read", () => {
    expect(parseManifest("pom.xml", "<project/>")).toBeNull();
  });
});

describe("sanitizeComponents", () => {
  it("keeps valid AI components and names the rest as skipped", () => {
    expect(
      sanitizeComponents([
        { name: " lodash ", version: "4.17.20", ecosystem: "NPM" },
        { name: "react", version: null, ecosystem: "npm" },
        { name: "thing", version: "1.0", ecosystem: "cobol" },
        { version: "1.0" },
        "junk",
      ]),
    ).toEqual({
      components: [{ name: "lodash", version: "4.17.20", ecosystem: "npm" }],
      skipped: ["react", "thing"],
    });
    expect(sanitizeComponents("nope")).toEqual({ components: [], skipped: [] });
  });
});

describe("extractJsonObject", () => {
  it("reads JSON wrapped in prose or a code fence", () => {
    expect(extractJsonObject('Here:\n```json\n{"components":[]}\n```')).toEqual(
      {
        components: [],
      },
    );
    expect(extractJsonObject("no json")).toBeNull();
    expect(extractJsonObject("{broken")).toBeNull();
  });
});
