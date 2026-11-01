"""Cloud Governance findings: Custodian dry-run matches read as findings.

A governance finding is one resource matched by a policy in the latest
completed run of that policy. Runs keep matched resources in
``CustodianRun.output["resources"]``; there are no upstream ``Finding`` rows.

The finding UID is ``custodian-<policy id>-<resource id>``, so triage keyed by
UID survives the next run. Severity comes from ``metadata.severity`` of the
policy in the YAML, else ``medium``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import yaml
from api.models import Role
from cloudsneeker_api.models import CustodianPolicy, CustodianRun
from cloudsneeker_api.reports.access import visible_provider_ids
from cloudsneeker_api.services.trivy_import import bounded_uid

GOVERNANCE_UID_PREFIX = "custodian-"
DEFAULT_SEVERITY = "medium"
SEVERITIES = ("critical", "high", "medium", "low", "informational")

# Same lookup order as the run page (``ui/cloudsneeker/lib/custodian-resources.ts``).
_ID_KEYS = (
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
)
_NAME_KEYS = ("Name", "name", "displayName", "DisplayName")
_REGION_KEYS = ("c7n:region", "Region", "region", "Location", "location")


@dataclass(frozen=True)
class PolicyRule:
    """One policy entry of a policy document."""

    name: str
    resource_type: str
    severity: str
    description: str


@dataclass
class GovernanceFinding:
    """One resource matched by a policy in its latest run."""

    uid: str
    policy_id: str
    policy_name: str
    rule_name: str
    provider_id: str
    run_id: str
    severity: str
    title: str
    description: str
    resource_id: str
    resource_name: str
    resource_type: str
    region: str
    last_seen_at: datetime | None
    first_seen_at: datetime | None
    raw: dict[str, Any] = field(default_factory=dict)


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return ""


def _first(resource: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = _text(resource.get(key))
        if value:
            return value
    return ""


def normalize_severity(value: Any) -> str:
    """Return a known severity, else the default."""
    text = _text(value).lower()
    return text if text in SEVERITIES else DEFAULT_SEVERITY


def policy_rules(policy_yaml: str) -> dict[str, PolicyRule]:
    """Rules of a policy document by name; unreadable YAML yields none."""
    try:
        parsed = yaml.safe_load(policy_yaml or "")
    except yaml.YAMLError:
        return {}
    if not isinstance(parsed, dict) or not isinstance(parsed.get("policies"), list):
        return {}
    rules: dict[str, PolicyRule] = {}
    for entry in parsed["policies"]:
        if not isinstance(entry, dict) or not _text(entry.get("name")):
            continue
        metadata = (
            entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
        )
        name = _text(entry["name"])
        rules[name] = PolicyRule(
            name=name,
            resource_type=_text(entry.get("resource")),
            severity=normalize_severity(metadata.get("severity")),
            description=_text(entry.get("description")) or _text(entry.get("comment")),
        )
    return rules


def resource_id(resource: dict[str, Any]) -> str:
    """Stable id of a matched resource (ARN, id, or Kubernetes namespace/name)."""
    value = _first(resource, _ID_KEYS)
    if value:
        return value
    metadata = resource.get("metadata")
    if isinstance(metadata, dict):
        uid = _text(metadata.get("uid"))
        if uid:
            return uid
        name = _text(metadata.get("name"))
        namespace = _text(metadata.get("namespace"))
        if name:
            return f"{namespace}/{name}" if namespace else name
    return _first(resource, _NAME_KEYS)


def resource_name(resource: dict[str, Any], fallback: str) -> str:
    """Display name: ``Name`` tag, Kubernetes name, name keys, else the id."""
    tags = resource.get("Tags")
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, dict) and tag.get("Key") in ("Name", "name"):
                value = _text(tag.get("Value"))
                if value:
                    return value
    metadata = resource.get("metadata")
    if isinstance(metadata, dict) and _text(metadata.get("name")):
        return _text(metadata["name"])
    return _first(resource, _NAME_KEYS) or fallback


def governance_uid(policy_id: str, resource_key: str) -> str:
    """Finding UID of a resource matched by a policy."""
    return bounded_uid(f"{GOVERNANCE_UID_PREFIX}{policy_id}-{resource_key}")


def latest_policy_runs(tenant_id: str, role: Role) -> list[CustodianRun]:
    """Latest completed run per policy the role can see."""
    runs = CustodianRun.objects.filter(
        tenant_id=tenant_id, status=CustodianRun.Status.COMPLETED
    )
    visible = visible_provider_ids(role)
    if visible is not None:
        runs = runs.filter(provider_id__in=list(visible))
    return list(
        runs.select_related("policy")
        .order_by("policy_id", "-finished_at", "-inserted_at")
        .distinct("policy_id")
    )


def _first_seen(tenant_id: str, policy_ids: list[str]) -> dict[str, datetime]:
    """Earliest completed run per policy (used as first seen)."""
    rows = (
        CustodianRun.objects.filter(
            tenant_id=tenant_id,
            policy_id__in=policy_ids,
            status=CustodianRun.Status.COMPLETED,
        )
        .order_by("policy_id", "finished_at")
        .distinct("policy_id")
        .values("policy_id", "finished_at")
    )
    return {str(row["policy_id"]): row["finished_at"] for row in rows}


def findings_for_run(
    run: CustodianRun, policy: CustodianPolicy, first_seen_at: datetime | None = None
) -> list[GovernanceFinding]:
    """Turn the matched resources of one run into findings (deduplicated by UID)."""
    rules = policy_rules(policy.policy_yaml)
    default_rule = next(iter(rules.values()), None)
    resources = (run.output or {}).get("resources") or []
    findings: dict[str, GovernanceFinding] = {}
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        rule_name = _text(resource.get("c7n:policy"))
        rule = rules.get(rule_name) or default_rule
        key = resource_id(resource)
        if not key:
            continue
        uid = governance_uid(str(policy.id), key)
        if uid in findings:
            continue
        rule_label = rule.name if rule else rule_name or policy.name
        findings[uid] = GovernanceFinding(
            uid=uid,
            policy_id=str(policy.id),
            policy_name=policy.name,
            rule_name=rule_label,
            provider_id=str(run.provider_id),
            run_id=str(run.id),
            severity=rule.severity if rule else DEFAULT_SEVERITY,
            title=rule_label,
            description=(rule.description if rule else "") or policy.description,
            resource_id=key,
            resource_name=resource_name(resource, key),
            resource_type=(rule.resource_type if rule else "") or "resource",
            region=_first(resource, _REGION_KEYS),
            last_seen_at=run.finished_at,
            first_seen_at=first_seen_at or run.finished_at,
            raw=resource,
        )
    return list(findings.values())


def governance_findings(tenant_id: str, role: Role) -> list[GovernanceFinding]:
    """Every current governance finding the role can see."""
    runs = latest_policy_runs(tenant_id, role)
    first_seen = _first_seen(tenant_id, [str(run.policy_id) for run in runs])
    findings: list[GovernanceFinding] = []
    for run in runs:
        findings.extend(
            findings_for_run(run, run.policy, first_seen.get(str(run.policy_id)))
        )
    return findings


def is_governance_uid(uid: str) -> bool:
    return uid.startswith(GOVERNANCE_UID_PREFIX)
