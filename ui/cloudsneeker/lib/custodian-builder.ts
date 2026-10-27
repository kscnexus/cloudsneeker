/** Schema-driven visual builder for common dry-run filters (AWS first). */

export const CUSTODIAN_BUILDER_RESOURCE = {
  AWS_S3: "aws.s3",
  AWS_EBS: "aws.ebs",
  AWS_EC2: "aws.ec2",
  AWS_EIP: "aws.elastic-ip",
} as const;

export type CustodianBuilderResource =
  (typeof CUSTODIAN_BUILDER_RESOURCE)[keyof typeof CUSTODIAN_BUILDER_RESOURCE];

export interface CustodianBuilderFilterOption {
  id: string;
  label: string;
  docsUrl: string;
  /** YAML fragment under filters: (indented list item body). */
  yaml: string;
}

export const CUSTODIAN_BUILDER_RESOURCES: Array<{
  value: CustodianBuilderResource;
  label: string;
}> = [
  { value: CUSTODIAN_BUILDER_RESOURCE.AWS_S3, label: "AWS S3" },
  { value: CUSTODIAN_BUILDER_RESOURCE.AWS_EBS, label: "AWS EBS" },
  { value: CUSTODIAN_BUILDER_RESOURCE.AWS_EC2, label: "AWS EC2" },
  { value: CUSTODIAN_BUILDER_RESOURCE.AWS_EIP, label: "AWS Elastic IP" },
];

const FILTERS: Record<CustodianBuilderResource, CustodianBuilderFilterOption[]> =
  {
    [CUSTODIAN_BUILDER_RESOURCE.AWS_S3]: [
      {
        id: "global-grants",
        label: "Public ACL grants",
        docsUrl:
          "https://cloudcustodian.io/docs/aws/resources/s3.html#aws-s3-filters-global-grants",
        yaml: "- type: global-grants",
      },
      {
        id: "public-block-acls",
        label: "BlockPublicAcls disabled",
        docsUrl:
          "https://cloudcustodian.io/docs/aws/resources/s3.html#aws-s3-filters-check-public-block",
        yaml: `- type: check-public-block
            BlockPublicAcls: false`,
      },
      {
        id: "public-block-policy",
        label: "BlockPublicPolicy disabled",
        docsUrl:
          "https://cloudcustodian.io/docs/aws/resources/s3.html#aws-s3-filters-check-public-block",
        yaml: `- type: check-public-block
            BlockPublicPolicy: false`,
      },
    ],
    [CUSTODIAN_BUILDER_RESOURCE.AWS_EBS]: [
      {
        id: "unattached",
        label: "No attachments",
        docsUrl: "https://cloudcustodian.io/docs/aws/resources/ebs.html",
        yaml: "- Attachments: []",
      },
      {
        id: "unencrypted",
        label: "Unencrypted",
        docsUrl: "https://cloudcustodian.io/docs/aws/resources/ebs.html",
        yaml: "- Encrypted: false",
      },
    ],
    [CUSTODIAN_BUILDER_RESOURCE.AWS_EC2]: [
      {
        id: "stopped",
        label: "State is stopped",
        docsUrl: "https://cloudcustodian.io/docs/aws/resources/ec2.html",
        yaml: `- type: value
        key: State.Name
        value: stopped`,
      },
    ],
    [CUSTODIAN_BUILDER_RESOURCE.AWS_EIP]: [
      {
        id: "unattached",
        label: "Not associated",
        docsUrl: "https://cloudcustodian.io/docs/aws/resources/elastic-ip.html",
        yaml: "- AssociationId: absent",
      },
    ],
  };

export function filtersForResource(
  resource: CustodianBuilderResource,
): CustodianBuilderFilterOption[] {
  return FILTERS[resource] ?? [];
}

export function buildCustodianPolicyYaml(input: {
  name: string;
  resource: CustodianBuilderResource;
  filterIds: string[];
  description?: string;
}): string {
  const filters = filtersForResource(input.resource).filter((item) =>
    input.filterIds.includes(item.id),
  );
  const filterBlock =
    filters.length === 0
      ? "    filters: []\n"
      : filters.length === 1
        ? `    filters:\n      ${filters[0].yaml}\n`
        : `    filters:\n      - or:\n${filters
            .map((item) =>
              item.yaml
                .split("\n")
                .map((line, index) =>
                  index === 0 ? `          ${line}` : `          ${line}`,
                )
                .join("\n"),
            )
            .join("\n")}\n`;

  const description = input.description
    ? `    description: ${input.description}\n`
    : "";

  return `policies:
  - name: ${input.name || "generated-policy"}
    resource: ${input.resource}
${description}${filterBlock}`;
}
