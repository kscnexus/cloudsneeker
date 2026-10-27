"""Pre-flight Custodian policy validation and dry-run error classification."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any

from cloudsneeker_api.services.custodian import (
    CustodianDryRunError,
    _resolve_custodian_bin,
    parse_policy_yaml,
)

ERROR_INVALID_POLICY = "invalid_policy"
ERROR_CREDENTIALS = "credentials"
ERROR_CLOUD_API = "cloud_api"
ERROR_TIMEOUT = "timeout"
ERROR_CANCELLED = "cancelled"
ERROR_UNKNOWN = "unknown"

CUSTODIAN_ERROR_CLASS = {
    "INVALID_POLICY": ERROR_INVALID_POLICY,
    "CREDENTIALS": ERROR_CREDENTIALS,
    "CLOUD_API": ERROR_CLOUD_API,
    "TIMEOUT": ERROR_TIMEOUT,
    "CANCELLED": ERROR_CANCELLED,
    "UNKNOWN": ERROR_UNKNOWN,
}

_CREDENTIAL_HINTS = (
    "unable to locate credentials",
    "invalidclienttokenid",
    "expiredtoken",
    "accessdenied",
    "unauthorized",
    "authfailure",
    "no usable",
    "credentials",
)
_POLICY_HINTS = (
    "invalid policy",
    "failed to validate",
    "is not valid under any of the given schemas",
    "unknown Error on policy",
    "schema",
)
_TIMEOUT_HINTS = ("timed out", "timeout", "deadline exceeded")


def validate_custodian_policy_schema(policy_yaml: str) -> None:
    """Structurally parse YAML then optionally run ``custodian validate``.

    Raises:
        CustodianDryRunError: When the policy document is invalid.
    """
    parse_policy_yaml(policy_yaml)
    _assert_no_apply_actions(policy_yaml)
    _validate_with_c7n_cli(policy_yaml)


def _assert_no_apply_actions(policy_yaml: str) -> None:
    """Reject policies that declare mutating actions (dry-run product boundary)."""
    parsed = parse_policy_yaml(policy_yaml)
    for index, policy in enumerate(parsed["policies"]):
        actions = policy.get("actions")
        if not actions:
            continue
        if isinstance(actions, list) and len(actions) == 0:
            continue
        raise CustodianDryRunError(
            f"Policy at index {index} declares actions; Cloudsneeker dry-run "
            "policies must omit actions."
        )


def _validate_with_c7n_cli(policy_yaml: str) -> None:
    """Call Cloud Custodian ``validate`` when the binary is available."""
    import subprocess

    skip = os.environ.get("C7N_SKIP_VALIDATE", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    if skip:
        return

    custodian_bin = _resolve_custodian_bin()
    with tempfile.TemporaryDirectory(prefix="cs-c7n-validate-") as tmp:
        policy_path = Path(tmp) / "policy.yml"
        policy_path.write_text(policy_yaml, encoding="utf-8")
        try:
            completed = subprocess.run(
                [custodian_bin, "validate", str(policy_path)],
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
        except FileNotFoundError:
            # Local/dev without c7n: structural checks already ran.
            return
        except subprocess.TimeoutExpired as exc:
            raise CustodianDryRunError(
                "Cloud Custodian policy validation timed out."
            ) from exc

        if completed.returncode == 0:
            return

        detail = (completed.stderr or completed.stdout or "invalid policy").strip()
        # Prefer the readable "Failed to validate…" slice when present.
        match = re.search(
            r"(Failed to validate policy.*|invalid policy file:.*)",
            detail,
            flags=re.IGNORECASE | re.DOTALL,
        )
        message = match.group(1).strip() if match else detail
        raise CustodianDryRunError(message[:2000])


def classify_custodian_error(message: str) -> str:
    """Classify a dry-run failure for UI display."""
    text = (message or "").lower()
    if not text:
        return ERROR_UNKNOWN
    if any(hint in text for hint in _TIMEOUT_HINTS):
        return ERROR_TIMEOUT
    if "cancel" in text:
        return ERROR_CANCELLED
    if any(hint in text for hint in _POLICY_HINTS):
        return ERROR_INVALID_POLICY
    if any(hint in text for hint in _CREDENTIAL_HINTS):
        return ERROR_CREDENTIALS
    if "error" in text or "exception" in text or "failed" in text:
        return ERROR_CLOUD_API
    return ERROR_UNKNOWN


def build_resources_preview(
    resources: list[dict[str, Any]], *, limit: int = 50
) -> list[dict[str, str]]:
    """Build a slim resource preview for list/summary payloads."""
    preview: list[dict[str, str]] = []
    for item in resources[:limit]:
        if not isinstance(item, dict):
            continue
        uid = _first_str(
            item,
            (
                "VolumeId",
                "InstanceId",
                "Arn",
                "id",
                "Id",
                "Name",
                "BucketName",
            ),
        )
        name = _tag_name(item) or _first_str(item, ("Name", "name")) or uid
        region = _first_str(
            item, ("c7n:region", "Region", "AvailabilityZone", "location")
        )
        preview.append(
            {
                "uid": uid or "—",
                "name": name or "—",
                "region": region or "—",
                "type": _first_str(item, ("Type", "type", "c7n:policy")) or "resource",
                "policy": _first_str(item, ("c7n:policy",)) or "—",
            }
        )
    return preview


def compute_resource_delta(
    current: list[dict[str, Any]],
    previous: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Compare matched resource UIDs between two dry-runs."""
    current_ids = {_resource_uid(item) for item in current if isinstance(item, dict)}
    current_ids.discard("")
    previous_ids = {
        _resource_uid(item) for item in (previous or []) if isinstance(item, dict)
    }
    previous_ids.discard("")
    return {
        "new": sorted(current_ids - previous_ids),
        "gone": sorted(previous_ids - current_ids),
        "still_matched": sorted(current_ids & previous_ids),
        "new_count": len(current_ids - previous_ids),
        "gone_count": len(previous_ids - current_ids),
        "still_matched_count": len(current_ids & previous_ids),
    }


def _resource_uid(item: dict[str, Any]) -> str:
    return _first_str(
        item,
        (
            "VolumeId",
            "InstanceId",
            "Arn",
            "id",
            "Id",
            "BucketName",
            "Name",
            "FunctionName",
        ),
    )


def _first_str(item: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, (int, float, bool)):
            return str(value)
    return ""


def _tag_name(item: dict[str, Any]) -> str:
    tags = item.get("Tags") or item.get("tags")
    if isinstance(tags, list):
        for entry in tags:
            if not isinstance(entry, dict):
                continue
            key = entry.get("Key") or entry.get("key")
            if key in {"Name", "name"}:
                value = entry.get("Value") or entry.get("value")
                if isinstance(value, str):
                    return value
    if isinstance(tags, dict):
        value = tags.get("Name") or tags.get("name")
        if isinstance(value, str):
            return value
    return ""
