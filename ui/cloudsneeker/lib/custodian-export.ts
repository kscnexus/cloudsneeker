import type { CustodianMatchedResource } from "@/cloudsneeker/lib/custodian-resources";

export function resourcesToCsv(resources: CustodianMatchedResource[]): string {
  const header = ["uid", "name", "type", "service", "region", "status", "policy"];
  const lines = [header.join(",")];
  for (const resource of resources) {
    lines.push(
      [
        resource.uid,
        resource.name,
        resource.type,
        resource.service,
        resource.region,
        resource.status,
        resource.policyName,
      ]
        .map(csvEscape)
        .join(","),
    );
  }
  return `${lines.join("\n")}\n`;
}

export function resourcesToJson(resources: CustodianMatchedResource[]): string {
  return `${JSON.stringify(
    resources.map((resource) => ({
      uid: resource.uid,
      name: resource.name,
      type: resource.type,
      service: resource.service,
      region: resource.region,
      status: resource.status,
      policy: resource.policyName,
      tags: resource.tags,
      raw: resource.raw,
    })),
    null,
    2,
  )}\n`;
}

export function downloadTextFile(
  filename: string,
  contents: string,
  mimeType: string,
): void {
  const blob = new Blob([contents], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

const csvEscape = (value: string): string => {
  if (/[",\n]/.test(value)) {
    return `"${value.replaceAll('"', '""')}"`;
  }
  return value;
};
