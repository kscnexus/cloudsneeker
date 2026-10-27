/** Normalize Cloud Custodian resources.json payloads into finding-like rows. */

export interface CustodianMatchedResource {
  id: string;
  uid: string;
  name: string;
  type: string;
  region: string;
  service: string;
  policyName: string;
  status: string;
  tags: Record<string, string>;
  raw: Record<string, unknown>;
}

interface CustodianOutputLike {
  resources?: unknown;
  policies?: Array<{ name?: string; resource_count?: number }>;
}

const UID_KEYS = [
  "VolumeId",
  "InstanceId",
  "DBInstanceIdentifier",
  "LoadBalancerArn",
  "BucketName",
  "FunctionName",
  "TableName",
  "ClusterArn",
  "QueueUrl",
  "TopicArn",
  "Arn",
  "arn",
  "selfLink",
  "id",
  "Id",
  "ID",
] as const;

const NAME_KEYS = ["Name", "name", "displayName", "DisplayName"] as const;

const REGION_KEYS = [
  "c7n:region",
  "Region",
  "region",
  "Location",
  "location",
  "LocationConstraint",
  "AvailabilityZone",
  "Placement",
] as const;

const STATUS_KEYS = [
  "State",
  "state",
  "Status",
  "status",
  "powerState",
  "ProvisioningState",
] as const;

const TYPE_KEYS = ["Type", "type", "ResourceType", "kind"] as const;

const AWS_REGION_FROM_AZ = /^([a-z]{2}(?:-[a-z]+)+-\d+)[a-z]?$/i;

const asRecord = (value: unknown): Record<string, unknown> | null => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
};

const asString = (value: unknown): string | null => {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return null;
};

const readFirstString = (
  resource: Record<string, unknown>,
  keys: readonly string[],
): string | null => {
  for (const key of keys) {
    const value = asString(resource[key]);
    if (value) return value;
  }
  return null;
};

const normalizeTags = (
  resource: Record<string, unknown>,
): Record<string, string> => {
  const tags: Record<string, string> = {};
  const rawTags = resource.Tags ?? resource.tags ?? resource.tagSet;

  if (Array.isArray(rawTags)) {
    for (const entry of rawTags) {
      const record = asRecord(entry);
      if (!record) continue;
      const key = asString(record.Key ?? record.key);
      const value = asString(record.Value ?? record.value);
      if (key && value) tags[key] = value;
    }
    return tags;
  }

  const record = asRecord(rawTags);
  if (record) {
    for (const [key, value] of Object.entries(record)) {
      const text = asString(value);
      if (text) tags[key] = text;
    }
  }
  return tags;
};

const normalizeRegion = (value: string | null): string => {
  if (!value) return "";
  const azMatch = value.match(AWS_REGION_FROM_AZ);
  // us-east-1a → us-east-1
  if (azMatch && /[a-z]$/i.test(value) && azMatch[1].length < value.length) {
    return azMatch[1];
  }
  return value;
};

const regionFromResource = (resource: Record<string, unknown>): string => {
  for (const key of REGION_KEYS) {
    const raw = resource[key];
    if (key === "Placement") {
      const placement = asRecord(raw);
      const az = placement ? asString(placement.AvailabilityZone) : null;
      if (az) return normalizeRegion(az);
      continue;
    }
    const value = asString(raw);
    if (value) return normalizeRegion(value);
  }

  const metadata = asRecord(resource.metadata);
  if (metadata) {
    const labels = asRecord(metadata.labels);
    const zone = asString(labels?.["topology.kubernetes.io/zone"]);
    if (zone) return normalizeRegion(zone);
  }
  return "";
};

const inferType = (resource: Record<string, unknown>): string => {
  const explicit = readFirstString(resource, TYPE_KEYS);
  if (explicit) return explicit;

  if (resource.VolumeId) return "aws.ebs";
  if (resource.InstanceId) return "aws.ec2";
  if (resource.BucketName || resource.Name === resource.BucketName)
    return "aws.s3";
  if (resource.DBInstanceIdentifier) return "aws.rds";
  if (resource.FunctionName) return "aws.lambda";
  if (resource.TableName) return "aws.dynamodb";
  if (asString(resource.id)?.includes("/virtualMachines/")) return "azure.vm";
  if (asString(resource.selfLink)?.includes("compute.googleapis.com")) {
    return "gcp.instance";
  }
  const metadata = asRecord(resource.metadata);
  if (metadata?.name && (resource.kind || metadata.namespace)) {
    return asString(resource.kind) || "kubernetes";
  }
  return "resource";
};

const inferService = (type: string): string => {
  if (!type || type === "resource") return "—";
  const parts = type.split(/[./]/).filter(Boolean);
  if (parts.length >= 2) return parts[1];
  return parts[0] || "—";
};

const nameFromResource = (
  resource: Record<string, unknown>,
  uid: string,
  tags: Record<string, string>,
): string => {
  if (tags.Name) return tags.Name;
  if (tags.name) return tags.name;
  const metadata = asRecord(resource.metadata);
  const metaName = metadata ? asString(metadata.name) : null;
  if (metaName) return metaName;
  return readFirstString(resource, NAME_KEYS) || uid || "—";
};

export function extractCustodianResourceUid(
  resource: Record<string, unknown>,
): string {
  const metadata = asRecord(resource.metadata);
  const metaUid =
    metadata &&
    (asString(metadata.uid) ||
      asString(metadata.name) ||
      (asString(metadata.namespace) && asString(metadata.name)
        ? `${metadata.namespace}/${metadata.name}`
        : null));
  if (metaUid) return metaUid;
  return readFirstString(resource, UID_KEYS) || "";
}

export function normalizeCustodianResources(
  output: CustodianOutputLike | null | undefined,
): CustodianMatchedResource[] {
  if (!output || !Array.isArray(output.resources)) return [];

  const fallbackPolicy =
    output.policies?.find((policy) => policy.name)?.name || "";

  return output.resources.flatMap((item, index) => {
    const resource = asRecord(item);
    if (!resource) return [];

    const tags = normalizeTags(resource);
    const uid = extractCustodianResourceUid(resource) || `resource-${index + 1}`;
    const type = inferType(resource);
    const policyName =
      asString(resource["c7n:policy"]) ||
      asString(resource.policy) ||
      fallbackPolicy ||
      "—";
    const status =
      readFirstString(resource, STATUS_KEYS) ||
      asString(asRecord(resource.properties)?.powerState) ||
      "matched";

    return [
      {
        id: `${uid}-${index}`,
        uid,
        name: nameFromResource(resource, uid, tags),
        type,
        region: regionFromResource(resource) || "—",
        service: inferService(type),
        policyName,
        status,
        tags,
        raw: resource,
      },
    ];
  });
}
