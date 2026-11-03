"""Built-in governance policy library for AWS, Azure and GCP.

Library policies live as data in ``custodian_library/<provider>.yaml``. Each
entry carries catalogue metadata (category, severity, framework tags, starter
flag) plus the Custodian ``resource`` and ``filters``. The policy YAML users add
to their workspace is rendered from that data, so every library policy is a
dry-run report: entries never declare ``actions``.
"""

from __future__ import annotations

from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

LIBRARY_DIR = Path(__file__).with_name("custodian_library")
LIBRARY_PROVIDERS = ("aws", "azure", "gcp")

# Category ids are stable API keys; order is the UI display order.
LIBRARY_CATEGORIES: dict[str, dict[str, str]] = {
    "identity": {
        "name": "Identity & access",
        "description": "Users, keys, roles and privileged access.",
    },
    "network": {
        "name": "Network",
        "description": "Exposure to the internet, firewalls and traffic paths.",
    },
    "encryption": {
        "name": "Encryption & data protection",
        "description": "Encryption at rest and in transit, keys and secrets.",
    },
    "logging": {
        "name": "Logging & monitoring",
        "description": "Audit trails, flow logs and threat detection.",
    },
    "compute": {
        "name": "Compute",
        "description": "Virtual machines, containers and serverless hardening.",
    },
    "storage": {
        "name": "Storage",
        "description": "Buckets, blobs and file shares.",
    },
    "database": {
        "name": "Databases",
        "description": "Managed database exposure and hardening.",
    },
    "backup": {
        "name": "Backup & resilience",
        "description": "Backups, retention, versioning and high availability.",
    },
    "cost": {
        "name": "Cost optimization",
        "description": "Idle, unattached and oversized resources.",
    },
    "tagging": {
        "name": "Tagging & hygiene",
        "description": "Ownership tags, defaults and stale resources.",
    },
}

LIBRARY_SEVERITIES = ("critical", "high", "medium", "low")

_REQUIRED_FIELDS = ("id", "name", "category", "severity", "resource", "description")


class CustodianLibraryError(ValueError):
    """Raised when a library data file is malformed."""


@lru_cache(maxsize=1)
def _load_library() -> tuple[dict[str, Any], ...]:
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for provider_type in LIBRARY_PROVIDERS:
        path = LIBRARY_DIR / f"{provider_type}.yaml"
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for raw in data.get("policies") or []:
            entry = _build_entry(provider_type, raw)
            if entry["id"] in seen:
                raise CustodianLibraryError(f"Duplicate library id {entry['id']!r}.")
            seen.add(entry["id"])
            entries.append(entry)
    return tuple(entries)


def _build_entry(provider_type: str, raw: dict[str, Any]) -> dict[str, Any]:
    missing = [field for field in _REQUIRED_FIELDS if not raw.get(field)]
    if missing:
        raise CustodianLibraryError(
            f"Library entry {raw.get('id')!r} is missing {', '.join(missing)}."
        )
    if raw["category"] not in LIBRARY_CATEGORIES:
        raise CustodianLibraryError(
            f"Library entry {raw['id']!r} has unknown category {raw['category']!r}."
        )
    if raw["severity"] not in LIBRARY_SEVERITIES:
        raise CustodianLibraryError(
            f"Library entry {raw['id']!r} has unknown severity {raw['severity']!r}."
        )
    if "actions" in raw:
        raise CustodianLibraryError(
            f"Library entry {raw['id']!r} declares actions; library policies are dry-run."
        )

    policy: dict[str, Any] = {
        "name": raw["id"],
        "resource": raw["resource"],
        "description": raw["description"],
    }
    if raw.get("filters"):
        policy["filters"] = raw["filters"]

    return {
        "id": raw["id"],
        "name": raw["name"],
        "description": raw["description"],
        "provider_type": provider_type,
        "category": raw["category"],
        "category_name": LIBRARY_CATEGORIES[raw["category"]]["name"],
        "severity": raw["severity"],
        "resource": raw["resource"],
        "frameworks": list(raw.get("frameworks") or []),
        "starter": bool(raw.get("starter", False)),
        "policy_yaml": render_policy_yaml(policy),
    }


def render_policy_yaml(policy: dict[str, Any]) -> str:
    """Render one Custodian policy mapping as a ``policies:`` document."""
    return yaml.safe_dump(
        {"policies": [policy]},
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=4096,
    )


def _copy(entry: dict[str, Any]) -> dict[str, Any]:
    return {**entry, "frameworks": list(entry["frameworks"])}


def list_library_policies(
    *,
    provider_type: str | None = None,
    category: str | None = None,
    search: str | None = None,
    starter_only: bool = False,
) -> list[dict[str, Any]]:
    """Return library policies matching the optional filters.

    Args:
        provider_type: ``aws``, ``azure`` or ``gcp``.
        category: A key of ``LIBRARY_CATEGORIES``.
        search: Case-insensitive text matched against name, description,
            resource and framework tags.
        starter_only: Only return the recommended starter policies.

    Returns:
        Library entries in catalogue order.
    """
    needle = (search or "").strip().lower()
    results = []
    for entry in _load_library():
        if provider_type and entry["provider_type"] != provider_type:
            continue
        if category and entry["category"] != category:
            continue
        if starter_only and not entry["starter"]:
            continue
        if needle and needle not in _search_text(entry):
            continue
        results.append(_copy(entry))
    return results


def _search_text(entry: dict[str, Any]) -> str:
    return " ".join(
        [
            entry["id"],
            entry["name"],
            entry["description"],
            entry["resource"],
            entry["category_name"],
            " ".join(entry["frameworks"]),
        ]
    ).lower()


def get_library_policy(policy_id: str) -> dict[str, Any] | None:
    """Return one library policy by id."""
    for entry in _load_library():
        if entry["id"] == policy_id:
            return _copy(entry)
    return None


def library_policy_ids_in_yaml(policy_yaml: str) -> set[str]:
    """Return library ids whose policy name appears in ``policy_yaml``."""
    try:
        parsed = yaml.safe_load(policy_yaml or "")
    except yaml.YAMLError:
        return set()
    if not isinstance(parsed, dict) or not isinstance(parsed.get("policies"), list):
        return set()
    known = {entry["id"] for entry in _load_library()}
    names = {
        str(policy.get("name"))
        for policy in parsed["policies"]
        if isinstance(policy, dict) and policy.get("name")
    }
    return names & known


def library_coverage(
    workspace_policies: Iterable[tuple[str, str]],
    *,
    provider_type: str | None = None,
) -> dict[str, Any]:
    """Summarise which library categories have policies in a workspace.

    Args:
        workspace_policies: ``(provider_type, policy_yaml)`` pairs for the
            tenant's governance policies.
        provider_type: Limit the summary to one cloud.

    Returns:
        ``installed_ids`` plus one row per provider and category with the
        library total and how many of those policies are in the workspace.
    """
    installed: set[str] = set()
    for _, policy_yaml in workspace_policies:
        installed |= library_policy_ids_in_yaml(policy_yaml)

    rows = []
    providers = (provider_type,) if provider_type else LIBRARY_PROVIDERS
    for provider in providers:
        for category_id, category in LIBRARY_CATEGORIES.items():
            ids = [
                entry["id"]
                for entry in _load_library()
                if entry["provider_type"] == provider
                and entry["category"] == category_id
            ]
            if not ids:
                continue
            rows.append(
                {
                    "provider_type": provider,
                    "category": category_id,
                    "category_name": category["name"],
                    "total": len(ids),
                    "active": len(installed.intersection(ids)),
                }
            )
    return {"installed_ids": sorted(installed), "categories": rows}


def library_categories() -> list[dict[str, str]]:
    """Return the category catalogue in display order."""
    return [
        {"id": category_id, **category}
        for category_id, category in LIBRARY_CATEGORIES.items()
    ]
