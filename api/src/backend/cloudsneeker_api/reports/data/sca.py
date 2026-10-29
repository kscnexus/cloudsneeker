"""Software composition analysis (SCA) report data."""

from __future__ import annotations

from typing import Any

from cloudsneeker_api.reports.catalog import SCA
from cloudsneeker_api.reports.data.common import (
    VULNERABILITY_Q,
    ScanScope,
    metadata_text,
    source_label,
)
from cloudsneeker_api.reports.data.findings_report import (
    FindingsReportSpec,
    assemble_findings_report,
)
from cloudsneeker_api.reports.schema import ReportData, ReportFilters

SCOPE = ScanScope(
    trivy_modes=frozenset({"repo", "fs", "sbom", "image", "k8s"}),
    prowler_provider_types=frozenset({"image"}),
)

COLUMNS: list[tuple[str, str]] = [
    ("severity", "Severity"),
    ("cve", "Vulnerability"),
    ("package", "Package"),
    ("installed_version", "Installed"),
    ("fixed_version", "Fixed in"),
    ("title", "Title"),
    ("provider", "Source"),
    ("target", "Target"),
    ("reference", "Reference"),
]


def sca_row(item: dict[str, Any], resource: dict[str, str]) -> dict[str, Any]:
    """Build an SCA row from Trivy vulnerability fields.

    Args:
        item: Finding values row.
        resource: Linked resource (``uid``, ``name``, ...).

    Returns:
        Row keyed by ``COLUMNS`` fields.
    """
    raw = item.get("raw_result") or {}
    metadata = item.get("check_metadata") or {}
    return {
        "severity": str(item["severity"]),
        "cve": str(raw.get("VulnerabilityID") or item["check_id"]),
        "package": str(
            raw.get("PkgName") or raw.get("PkgID") or resource.get("name") or ""
        ),
        "installed_version": str(raw.get("InstalledVersion") or ""),
        "fixed_version": str(raw.get("FixedVersion") or ""),
        "title": str(
            metadata_text(metadata, "CheckTitle")
            or raw.get("Title")
            or item["check_id"]
        )[:256],
        "provider": source_label(item),
        "target": str(resource.get("uid") or ""),
        "reference": str(raw.get("PrimaryURL") or ""),
    }


SPEC = FindingsReportSpec(
    report_type=SCA,
    title="Software Composition Analysis Report",
    scope=SCOPE,
    noun="vulnerable dependencies",
    empty_state=(
        "No dependency scans in scope. Add a repository, filesystem, SBOM, or "
        "image target in Application Security to populate this report."
    ),
    include_q=VULNERABILITY_Q,
    detail_title="Vulnerable dependencies",
    columns=COLUMNS,
    row_builder=sca_row,
)


def assemble(tenant_id: str, filters: ReportFilters) -> ReportData:
    """Assemble the SCA report.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters.

    Returns:
        ``ReportData`` with fixable-vulnerability KPIs.
    """
    data = assemble_findings_report(tenant_id, filters, SPEC)
    if not data.is_empty:
        table = next(t for t in data.tables if t.key == "findings")
        data.kpis["fixable_in_table"] = sum(
            1 for row in table.rows if row.get("fixed_version")
        )
        data.kpis["unique_packages_in_table"] = len(
            {row.get("package") for row in table.rows if row.get("package")}
        )
    return data
