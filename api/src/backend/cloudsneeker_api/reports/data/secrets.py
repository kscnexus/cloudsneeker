"""Secrets report data (code, images, and cloud accounts)."""

from __future__ import annotations

from typing import Any

from cloudsneeker_api.reports.catalog import SECRETS
from cloudsneeker_api.reports.data.common import (
    SECRET_Q,
    ScanScope,
    default_finding_row,
)
from cloudsneeker_api.reports.data.findings_report import (
    FindingsReportSpec,
    assemble_findings_report,
)
from cloudsneeker_api.reports.schema import ReportData, ReportFilters

SCOPE = ScanScope(
    cloud=True,
    trivy_modes=frozenset({"iac", "image", "fs", "repo", "sbom", "k8s", "sast"}),
    prowler_provider_types=frozenset({"iac", "image"}),
)

COLUMNS: list[tuple[str, str]] = [
    ("severity", "Severity"),
    ("check_id", "Rule"),
    ("title", "Title"),
    ("provider", "Source"),
    ("location", "Location"),
    ("detail", "Detail"),
]


def secret_row(item: dict[str, Any], resource: dict[str, str]) -> dict[str, Any]:
    """Build a secrets row that never repeats the matched secret value.

    Trivy stores the (redacted) match in ``status_extended``; the row shows the
    secret category instead so reports never carry key material.

    Args:
        item: Finding values row.
        resource: Linked resource.

    Returns:
        Row keyed by ``COLUMNS`` fields.
    """
    base = default_finding_row(item, resource)
    raw = item.get("raw_result") or {}
    line = raw.get("StartLine")
    location = resource.get("uid") or resource.get("name") or ""
    if location and line:
        location = f"{location}:{line}"
    is_trivy_secret = "RuleID" in raw
    detail = raw.get("Category") if is_trivy_secret else base["detail"]
    return {
        "severity": base["severity"],
        "check_id": base["check_id"],
        "title": base["title"],
        "provider": base["provider"],
        "location": location,
        "detail": str(detail or "")[:500],
    }


SPEC = FindingsReportSpec(
    report_type=SECRETS,
    title="Secrets Exposure Report",
    scope=SCOPE,
    noun="exposed secrets",
    empty_state=(
        "No scans in scope. Run a cloud, repository, or image scan to look for "
        "exposed secrets."
    ),
    include_q=SECRET_Q,
    detail_title="Exposed secrets",
    columns=COLUMNS,
    row_builder=secret_row,
)


def assemble(tenant_id: str, filters: ReportFilters) -> ReportData:
    """Assemble the secrets report.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters.

    Returns:
        ``ReportData`` limited to secret findings across sources.
    """
    return assemble_findings_report(tenant_id, filters, SPEC)
