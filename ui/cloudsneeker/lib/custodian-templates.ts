/** Curated Custodian dry-run starters (mirrors API templates). */

export interface CustodianTemplate {
  id: string;
  name: string;
  description: string;
  providerTypes: string[];
  prowlerCheckIds: string[];
  policyYaml: string;
}

export interface CustodianPack {
  id: string;
  name: string;
  description: string;
  providerTypes: string[];
  templateIds: string[];
}

export const CUSTODIAN_TEMPLATES = [
  {
    id: "aws-public-s3",
    name: "Public S3 buckets",
    description:
      "Buckets with public ACL grants or public-access block disabled.",
    providerTypes: ["aws"],
    prowlerCheckIds: ["s3_bucket_public_access"],
    policyYaml: `policies:
  - name: public-s3-buckets
    resource: aws.s3
    description: Public ACL or open public-access block
    filters:
      - or:
          - type: global-grants
          - type: check-public-block
            BlockPublicAcls: false
          - type: check-public-block
            BlockPublicPolicy: false
          - type: check-public-block
            IgnorePublicAcls: false
          - type: check-public-block
            RestrictPublicBuckets: false
`,
  },
  {
    id: "aws-unused-ebs",
    name: "Unused EBS volumes",
    description: "EBS volumes with no attachments.",
    providerTypes: ["aws"],
    prowlerCheckIds: ["ec2_ebs_volume_unused"],
    policyYaml: `policies:
  - name: unused-ebs
    resource: aws.ebs
    filters:
      - Attachments: []
`,
  },
  {
    id: "aws-unattached-eip",
    name: "Unattached Elastic IPs",
    description:
      "Elastic IPs not associated with an instance or network interface.",
    providerTypes: ["aws"],
    prowlerCheckIds: ["ec2_elastic_ip_unassigned"],
    policyYaml: `policies:
  - name: unattached-eip
    resource: aws.elastic-ip
    filters:
      - AssociationId: absent
`,
  },
  {
    id: "aws-stopped-instances",
    name: "Stopped EC2 instances",
    description: "EC2 instances in the stopped state.",
    providerTypes: ["aws"],
    prowlerCheckIds: ["ec2_instance_managed_by_ssm"],
    policyYaml: `policies:
  - name: stopped-ec2
    resource: aws.ec2
    filters:
      - type: value
        key: State.Name
        value: stopped
`,
  },
  {
    id: "aws-unencrypted-ebs",
    name: "Unencrypted EBS volumes",
    description: "EBS volumes that are not encrypted.",
    providerTypes: ["aws"],
    prowlerCheckIds: ["ec2_ebs_volume_encryption"],
    policyYaml: `policies:
  - name: unencrypted-ebs
    resource: aws.ebs
    filters:
      - Encrypted: false
`,
  },
  {
    id: "azure-stopped-vm",
    name: "Stopped Azure VMs",
    description: "Virtual machines reported as stopped / deallocated.",
    providerTypes: ["azure"],
    prowlerCheckIds: [],
    policyYaml: `policies:
  - name: stopped-azure-vm
    resource: azure.vm
    filters:
      - type: value
        key: properties.powerState
        op: contains
        value: stopped
`,
  },
  {
    id: "gcp-stopped-instance",
    name: "Stopped GCP instances",
    description: "Compute Engine instances that are terminated.",
    providerTypes: ["gcp"],
    prowlerCheckIds: [],
    policyYaml: `policies:
  - name: stopped-gcp-instance
    resource: gcp.instance
    filters:
      - type: value
        key: status
        value: TERMINATED
`,
  },
] as const satisfies readonly CustodianTemplate[];

export const CUSTODIAN_PACKS = [
  {
    id: "aws-hygiene",
    name: "AWS hygiene pack",
    description: "Public S3, unused/unencrypted EBS, and unattached EIPs.",
    providerTypes: ["aws"],
    templateIds: [
      "aws-public-s3",
      "aws-unused-ebs",
      "aws-unencrypted-ebs",
      "aws-unattached-eip",
    ],
  },
] as const satisfies readonly CustodianPack[];

export function templatesForProvider(
  providerType: string | undefined,
): CustodianTemplate[] {
  if (!providerType) return [...CUSTODIAN_TEMPLATES];
  return CUSTODIAN_TEMPLATES.filter((item) =>
    item.providerTypes.includes(providerType),
  );
}

export function packsForProvider(
  providerType: string | undefined,
): CustodianPack[] {
  if (!providerType) return [...CUSTODIAN_PACKS];
  return CUSTODIAN_PACKS.filter((item) =>
    item.providerTypes.includes(providerType),
  );
}

export function findingsHrefForChecks(checkIds: string[]): string | null {
  if (checkIds.length === 0) return null;
  const params = new URLSearchParams();
  params.set("filter[check_id]", checkIds[0]);
  return `/findings?${params.toString()}`;
}

export function templatesForProwlerChecks(
  checkIds: string[],
): CustodianTemplate[] {
  if (checkIds.length === 0) return [];
  const wanted = new Set(checkIds);
  return CUSTODIAN_TEMPLATES.filter((item) =>
    item.prowlerCheckIds.some((checkId) => wanted.has(checkId)),
  );
}

export function allMappedProwlerCheckIds(): string[] {
  const ids = new Set<string>();
  for (const item of CUSTODIAN_TEMPLATES) {
    for (const checkId of item.prowlerCheckIds) ids.add(checkId);
  }
  return [...ids];
}
