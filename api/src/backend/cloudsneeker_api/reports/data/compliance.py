"""Compliance framework report data."""

from __future__ import annotations

from typing import Any

from api.models import ComplianceRequirementOverview, Scan, StateChoices
from cloudsneeker_api.reports.catalog import COMPLIANCE
from cloudsneeker_api.reports.data.common import (
    ScanScope,
    aggregate_findings,
    findings_for,
    findings_table,
    grade_for,
    remediation_priorities,
    requirement_status,
    risk_table,
    scope_scans,
    top_risks,
)
from cloudsneeker_api.reports.schema import ReportData, ReportFilters, ReportTable
from django.utils import timezone

# Compliance overviews come from engine scans of every provider type.
SCOPE = ScanScope(cloud=True, prowler_provider_types=frozenset({"iac", "image"}))

REQUIREMENT_COLUMNS: list[tuple[str, str]] = [
    ("requirement_id", "Requirement"),
    ("description", "Description"),
    ("status", "Status"),
    ("passed_findings", "Passed findings"),
    ("failed_findings", "Failed findings"),
    ("failed_checks", "Failed checks"),
    ("providers", "Sources"),
]


def finding_compliance_key(framework: str, version: str) -> str:
    """Return the key the SDK uses in ``Finding.compliance``.

    The SDK keys a finding's compliance map by ``"<Framework>-<Version>"``
    (``"CIS-2.0"``), or by the framework alone when it has no version.
    """
    return f"{framework}-{version}" if version else framework


def compliance_scan_ids(tenant_id: str, filters: ReportFilters) -> list:
    """Return the scans the compliance report reads.

    A pinned ``scan_id`` must be a completed scan of an in-scope provider;
    otherwise the latest engine scan of every provider is used.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters.

    Returns:
        Scan ids (empty when the pinned scan is not visible).
    """
    if filters.scan_id:
        queryset = Scan.all_objects.filter(
            tenant_id=tenant_id,
            id=filters.scan_id,
            state=StateChoices.COMPLETED,
            provider__is_deleted=False,
        )
        if filters.provider_ids:
            queryset = queryset.filter(provider_id__in=filters.provider_ids)
        return list(queryset.values_list("id", flat=True))
    # One scan per provider: both cloud and IaC / image engine scans.
    picked: dict[str, Any] = {}
    rows = scope_scans(tenant_id, filters, SCOPE).latest_first().values_list(
        "id", "provider_id"
    )
    for scan_id, provider_id in rows.iterator(chunk_size=2000):
        picked.setdefault(str(provider_id), scan_id)
    return list(picked.values())


def requirement_rows(
    tenant_id: str, scan_ids: list, compliance_id: str
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Combine per-scan, per-region requirement rows into one row each.

    Args:
        tenant_id: Tenant UUID string.
        scan_ids: Scans to read.
        compliance_id: Framework id.

    Returns:
        ``(rows, framework_info)``; rows are sorted failing first.
    """
    combined: dict[str, dict[str, Any]] = {}
    info = {"framework": compliance_id, "version": ""}
    queryset = ComplianceRequirementOverview.objects.filter(
        tenant_id=tenant_id, scan_id__in=scan_ids, compliance_id=compliance_id
    ).values(
        "requirement_id",
        "description",
        "requirement_status",
        "passed_findings",
        "total_findings",
        "failed_checks",
        "framework",
        "version",
        "scan__provider_id",
    )
    for row in queryset:
        info["framework"] = row["framework"] or info["framework"]
        info["version"] = row["version"] or info["version"]
        entry = combined.setdefault(
            row["requirement_id"],
            {
                "requirement_id": row["requirement_id"],
                "description": (row["description"] or "")[:500],
                "statuses": set(),
                "passed_findings": 0,
                "failed_findings": 0,
                "failed_checks": 0,
                "provider_ids": set(),
            },
        )
        entry["statuses"].add(str(row["requirement_status"]))
        passed = int(row["passed_findings"] or 0)
        entry["passed_findings"] += passed
        entry["failed_findings"] += max(0, int(row["total_findings"] or 0) - passed)
        entry["failed_checks"] += int(row["failed_checks"] or 0)
        entry["provider_ids"].add(str(row["scan__provider_id"]))

    rows = []
    for entry in combined.values():
        rows.append(
            {
                "requirement_id": entry["requirement_id"],
                "description": entry["description"],
                "status": requirement_status(entry["statuses"]),
                "passed_findings": entry["passed_findings"],
                "failed_findings": entry["failed_findings"],
                "failed_checks": entry["failed_checks"],
                "providers": len(entry["provider_ids"]),
            }
        )
    order = {"FAIL": 0, "MANUAL": 1, "PASS": 2}
    rows.sort(key=lambda item: (order[item["status"]], item["requirement_id"]))
    return rows, info


def assemble(tenant_id: str, filters: ReportFilters) -> ReportData:
    """Assemble the compliance report for ``filters.compliance_id``.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters (``compliance_id`` required).

    Returns:
        ``ReportData`` with requirement posture and failing findings.
    """
    compliance_id = filters.compliance_id or ""
    data = ReportData(
        report_type=COMPLIANCE,
        title=f"Compliance Report: {compliance_id}",
        generated_at=timezone.now(),
        filters=filters,
    )
    scan_ids = compliance_scan_ids(tenant_id, filters)
    rows, info = requirement_rows(tenant_id, scan_ids, compliance_id) if scan_ids else ([], {})
    if not rows:
        data.empty_state = (
            f"No compliance results for {compliance_id} in scope. Run a scan of a "
            "provider this framework covers."
        )
        data.headline = data.empty_state
        return data

    passed = sum(1 for row in rows if row["status"] == "PASS")
    failed = sum(1 for row in rows if row["status"] == "FAIL")
    manual = sum(1 for row in rows if row["status"] == "MANUAL")
    scored = passed + failed
    pass_pct = round(100.0 * passed / scored, 1) if scored else None
    data.title = f"Compliance Report: {info['framework']} {info['version']}".strip()
    data.score = pass_pct
    data.grade = grade_for(pass_pct)
    data.kpis = {
        "framework": info["framework"],
        "version": info["version"],
        "requirements": len(rows),
        "requirements_passed": passed,
        "requirements_failed": failed,
        "requirements_manual": manual,
        "pass_pct": pass_pct,
        "scans_in_scope": len(scan_ids),
    }
    data.compliance = [
        {
            "compliance_id": compliance_id,
            "passed": passed,
            "failed": failed,
            "manual": manual,
            "total": len(rows),
            "pass_pct": pass_pct,
        }
    ]
    pct_text = f"{pass_pct}%" if pass_pct is not None else "no scored"
    data.headline = (
        f"{info['framework']} {info['version']}: {pct_text} of requirements pass; "
        f"{failed} failing, {manual} need manual review. Grade {data.grade}."
    ).replace("  ", " ")

    queryset = findings_for(tenant_id, scan_ids, filters).filter(
        compliance__has_key=finding_compliance_key(info["framework"], info["version"])
    )
    stats = aggregate_findings(queryset)
    data.severity_totals = dict(stats.fail_by_severity)
    data.status_totals = dict(stats.status)
    data.top_risks = top_risks(queryset, limit=10)
    data.remediation = remediation_priorities(data.top_risks)
    data.tables = [
        ReportTable(
            key="requirements",
            title="Requirements",
            columns=REQUIREMENT_COLUMNS,
            rows=rows,
            total=len(rows),
        ),
        risk_table(data.top_risks),
        findings_table("findings", "Failed findings mapped to this framework", queryset),
    ]
    return data
