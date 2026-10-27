"""Curated Cloud Custodian dry-run policy templates and packs.

Templates are validated YAML starters. Cloudsneeker never enables apply mode.
"""

from __future__ import annotations

from typing import Any

# Template ids are stable API keys.
CUSTODIAN_TEMPLATES: dict[str, dict[str, Any]] = {
    "aws-public-s3": {
        "id": "aws-public-s3",
        "name": "Public S3 buckets",
        "description": "Buckets with public ACL grants or public-access block disabled.",
        "provider_types": ["aws"],
        "prowler_check_ids": ["s3_bucket_public_access"],
        "policy_yaml": """policies:
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
""",
    },
    "aws-unused-ebs": {
        "id": "aws-unused-ebs",
        "name": "Unused EBS volumes",
        "description": "EBS volumes with no attachments.",
        "provider_types": ["aws"],
        "prowler_check_ids": ["ec2_ebs_volume_unused"],
        "policy_yaml": """policies:
  - name: unused-ebs
    resource: aws.ebs
    filters:
      - Attachments: []
""",
    },
    "aws-unattached-eip": {
        "id": "aws-unattached-eip",
        "name": "Unattached Elastic IPs",
        "description": "Elastic IPs not associated with an instance or network interface.",
        "provider_types": ["aws"],
        "prowler_check_ids": ["ec2_elastic_ip_unassigned"],
        "policy_yaml": """policies:
  - name: unattached-eip
    resource: aws.elastic-ip
    filters:
      - AssociationId: absent
""",
    },
    "aws-stopped-instances": {
        "id": "aws-stopped-instances",
        "name": "Stopped EC2 instances",
        "description": "EC2 instances in the stopped state.",
        "provider_types": ["aws"],
        "prowler_check_ids": ["ec2_instance_managed_by_ssm"],
        "policy_yaml": """policies:
  - name: stopped-ec2
    resource: aws.ec2
    filters:
      - type: value
        key: State.Name
        value: stopped
""",
    },
    "aws-unencrypted-ebs": {
        "id": "aws-unencrypted-ebs",
        "name": "Unencrypted EBS volumes",
        "description": "EBS volumes that are not encrypted.",
        "provider_types": ["aws"],
        "prowler_check_ids": ["ec2_ebs_volume_encryption"],
        "policy_yaml": """policies:
  - name: unencrypted-ebs
    resource: aws.ebs
    filters:
      - Encrypted: false
""",
    },
    "azure-stopped-vm": {
        "id": "azure-stopped-vm",
        "name": "Stopped Azure VMs",
        "description": "Virtual machines reported as stopped / deallocated.",
        "provider_types": ["azure"],
        "prowler_check_ids": [],
        "policy_yaml": """policies:
  - name: stopped-azure-vm
    resource: azure.vm
    filters:
      - type: value
        key: properties.powerState
        op: contains
        value: stopped
""",
    },
    "gcp-stopped-instance": {
        "id": "gcp-stopped-instance",
        "name": "Stopped GCP instances",
        "description": "Compute Engine instances that are terminated.",
        "provider_types": ["gcp"],
        "prowler_check_ids": [],
        "policy_yaml": """policies:
  - name: stopped-gcp-instance
    resource: gcp.instance
    filters:
      - type: value
        key: status
        value: TERMINATED
""",
    },
}

CUSTODIAN_PACKS: dict[str, dict[str, Any]] = {
    "aws-hygiene": {
        "id": "aws-hygiene",
        "name": "AWS hygiene pack",
        "description": "Public S3, unused/unencrypted EBS, and unattached EIPs.",
        "provider_types": ["aws"],
        "template_ids": [
            "aws-public-s3",
            "aws-unused-ebs",
            "aws-unencrypted-ebs",
            "aws-unattached-eip",
        ],
    },
}


def list_templates(*, provider_type: str | None = None) -> list[dict[str, Any]]:
    """Return template metadata, optionally filtered by provider type."""
    templates = list(CUSTODIAN_TEMPLATES.values())
    if provider_type:
        templates = [
            item
            for item in templates
            if provider_type in item["provider_types"]
        ]
    return [
        {
            "id": item["id"],
            "name": item["name"],
            "description": item["description"],
            "provider_types": list(item["provider_types"]),
            "prowler_check_ids": list(item["prowler_check_ids"]),
            "policy_yaml": item["policy_yaml"],
        }
        for item in templates
    ]


def get_template(template_id: str) -> dict[str, Any] | None:
    """Return one template by id."""
    item = CUSTODIAN_TEMPLATES.get(template_id)
    if item is None:
        return None
    return {
        "id": item["id"],
        "name": item["name"],
        "description": item["description"],
        "provider_types": list(item["provider_types"]),
        "prowler_check_ids": list(item["prowler_check_ids"]),
        "policy_yaml": item["policy_yaml"],
    }


def list_packs(*, provider_type: str | None = None) -> list[dict[str, Any]]:
    """Return pack metadata."""
    packs = list(CUSTODIAN_PACKS.values())
    if provider_type:
        packs = [item for item in packs if provider_type in item["provider_types"]]
    return [
        {
            "id": item["id"],
            "name": item["name"],
            "description": item["description"],
            "provider_types": list(item["provider_types"]),
            "template_ids": list(item["template_ids"]),
        }
        for item in packs
    ]


def get_pack(pack_id: str) -> dict[str, Any] | None:
    """Return one pack by id."""
    item = CUSTODIAN_PACKS.get(pack_id)
    if item is None:
        return None
    return {
        "id": item["id"],
        "name": item["name"],
        "description": item["description"],
        "provider_types": list(item["provider_types"]),
        "template_ids": list(item["template_ids"]),
    }


def prowler_check_ids_for_policy_yaml(policy_yaml: str) -> list[str]:
    """Best-effort map of policy resource/name to known Finding check ids."""
    text = (policy_yaml or "").lower()
    matched: list[str] = []
    for item in CUSTODIAN_TEMPLATES.values():
        resource_hint = ""
        for line in item["policy_yaml"].splitlines():
            if "resource:" in line:
                resource_hint = line.split("resource:", 1)[1].strip().lower()
                break
        if resource_hint and resource_hint in text:
            for check_id in item["prowler_check_ids"]:
                if check_id not in matched:
                    matched.append(check_id)
    return matched
