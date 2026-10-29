"""Static application security testing (SAST) report data."""

from __future__ import annotations

from typing import Any

from cloudsneeker_api.reports.catalog import SAST
from cloudsneeker_api.reports.data.common import ScanScope, default_finding_row
from cloudsneeker_api.reports.data.findings_report import (
    FindingsReportSpec,
    assemble_findings_report,
)
from cloudsneeker_api.reports.schema import ReportData, ReportFilters

SAST_MODE = "sast"
SCOPE = ScanScope(trivy_modes=frozenset({SAST_MODE}))

COLUMNS: list[tuple[str, str]] = [
    ("severity", "Severity"),
    ("check_id", "Rule"),
    ("title", "Title"),
    ("location", "Location"),
    ("provider", "Repository"),
    ("cwe", "CWE"),
    ("detail", "Detail"),
]

EMPTY_STATE = (
    "No static analysis scans yet. Add a repository target with the SAST mode "
    "in Application Security to populate this report."
)


def _location(raw: dict[str, Any], resource: dict[str, str]) -> str:
    path = raw.get("path") or raw.get("Path") or resource.get("uid") or ""
    start = raw.get("start")
    line = raw.get("StartLine") or (start.get("line") if isinstance(start, dict) else None)
    return f"{path}:{line}" if path and line else str(path)


def _cwe(raw: dict[str, Any], metadata: dict[str, Any]) -> str:
    extra = raw.get("extra") if isinstance(raw.get("extra"), dict) else {}
    meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    cwe = meta.get("cwe") or raw.get("CWE") or metadata.get("CWE") or ""
    if isinstance(cwe, list):
        return ", ".join(str(item) for item in cwe)
    return str(cwe)


def sast_row(item: dict[str, Any], resource: dict[str, str]) -> dict[str, Any]:
    """Build a SAST row; tolerant of OpenGrep and generic finding layouts.

    Args:
        item: Finding values row.
        resource: Linked resource.

    Returns:
        Row keyed by ``COLUMNS`` fields.
    """
    base = default_finding_row(item, resource)
    raw = item.get("raw_result") or {}
    metadata = item.get("check_metadata") or {}
    return {
        "severity": base["severity"],
        "check_id": base["check_id"],
        "title": base["title"],
        "location": _location(raw, resource),
        "provider": base["provider"],
        "cwe": _cwe(raw, metadata),
        "detail": base["detail"],
    }


SPEC = FindingsReportSpec(
    report_type=SAST,
    title="Static Application Security Report",
    scope=SCOPE,
    noun="code weaknesses",
    empty_state=EMPTY_STATE,
    detail_title="Code weaknesses",
    columns=COLUMNS,
    row_builder=sast_row,
)


def assemble(tenant_id: str, filters: ReportFilters) -> ReportData:
    """Assemble the SAST report (empty-state aware).

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters.

    Returns:
        ``ReportData``; ``empty_state`` explains how to enable SAST.
    """
    return assemble_findings_report(tenant_id, filters, SPEC)
