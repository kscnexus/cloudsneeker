"""Rows for the shared ``Scan`` / ``Finding`` tables.

Reports, alerts, the area findings list, triage and the outbound
integrations read those tables, so every scan keeps writing them. The row
shape is the one ``services.trivy_import`` has always written; the UID is
the ASPM finding's UID, which is also the triage key.
"""

from __future__ import annotations

from typing import Any

from cloudsneeker_api.appsec.parser import (
    CATEGORY_LICENSE,
    CATEGORY_MISCONFIGURATION,
    CATEGORY_SECRET,
    CATEGORY_VULNERABILITY,
    NormalizedFinding,
)

# The shared severity scale has no "unknown"; it reads as low there, as
# before. The ASPM finding keeps the real value.
SHARED_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "unknown": "low",
}


def remediation_text(finding: NormalizedFinding) -> str:
    """One-paragraph fix guidance for a finding."""
    if finding.category == CATEGORY_VULNERABILITY:
        if finding.fixed_version:
            installed = finding.pkg_version or "the installed version"
            return (
                f"Upgrade {finding.pkg_name} from {installed} to "
                f"{finding.fixed_version} or later."
            )
        status = finding.details.get("status") or ""
        note = f" The vendor status is '{status}'." if status else ""
        return (
            f"No fixed version of {finding.pkg_name} is published yet.{note} "
            "Reduce exposure of the affected component, or replace it."
        )
    if finding.category == CATEGORY_MISCONFIGURATION:
        return str(
            finding.details.get("resolution")
            or "Change the configuration as the check description explains."
        )
    if finding.category == CATEGORY_SECRET:
        return (
            "Revoke and rotate this credential now; it must be treated as "
            "leaked. Then remove it from the file and from version history, "
            "and load it from a secret manager instead."
        )
    if finding.category == CATEGORY_LICENSE:
        category = finding.details.get("license_category") or "unknown"
        return (
            f"The {finding.rule_id} license is classified as {category}. "
            "Confirm with your license policy whether this use is allowed, "
            "replace the component, or record an exception."
        )
    return str(finding.details.get("resolution") or "")


def shared_row(finding: NormalizedFinding, uid: str, *, mode: str) -> dict[str, Any]:
    """Build the shared ``Finding`` field mapping for one finding.

    Args:
        finding: Normalized finding.
        uid: UID assigned by the lifecycle (unique per tenant).
        mode: Target type, stored as the provider label of the row.

    Returns:
        Mapping accepted by ``trivy_import.import_trivy_report``.
    """
    severity = SHARED_SEVERITY.get(finding.severity, "low")
    service = {
        CATEGORY_SECRET: "secret",
        CATEGORY_LICENSE: "license",
    }.get(finding.category, finding.finding_type or mode)
    resource_type = finding.ecosystem or finding.finding_type or mode
    if (
        finding.category in (CATEGORY_VULNERABILITY, CATEGORY_LICENSE)
        and finding.pkg_name
    ):
        resource_uid = f"{finding.location}:{finding.pkg_name}"
        resource_name = finding.pkg_name
    else:
        resource_uid = finding.location or finding.file_path
        resource_name = finding.file_path or finding.location
    if finding.category == CATEGORY_SECRET:
        status_extended = finding.details.get("match") or finding.title
    elif finding.category == CATEGORY_MISCONFIGURATION:
        status_extended = (
            finding.details.get("message") or finding.description or finding.title
        )
    else:
        status_extended = finding.description or finding.primary_url or finding.title
    remediation = remediation_text(finding)
    return {
        "uid": uid,
        "status": "FAIL",
        "status_extended": str(status_extended)[:5000],
        "severity": severity,
        "impact": severity,
        "check_id": finding.rule_id[:100],
        "check_metadata": {
            "CheckID": finding.rule_id[:100],
            "CheckTitle": finding.title[:256],
            "Description": (finding.description or finding.title)[:2000],
            "Severity": severity,
            "Provider": "trivy",
            "ServiceName": str(service)[:100],
            "ResourceType": str(resource_type)[:100],
            "RelatedUrl": finding.primary_url,
            "Remediation": {
                "Code": {"CLI": "", "NativeIaC": "", "Other": "", "Terraform": ""},
                "Recommendation": {
                    "Text": remediation[:2000],
                    "Url": finding.primary_url,
                },
            },
        },
        "raw_result": finding.raw,
        "resource_regions": ["global"],
        "resource_services": [str(service)[:100]],
        "resource_types": [str(resource_type)[:100]],
        "resource_uid": str(resource_uid)[:300] or "scan-target",
        "resource_name": str(resource_name)[:300] or "scan-target",
    }
