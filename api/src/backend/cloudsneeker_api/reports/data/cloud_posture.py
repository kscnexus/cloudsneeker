"""Cloud posture report data."""

from __future__ import annotations

from cloudsneeker_api.reports.catalog import CLOUD_POSTURE
from cloudsneeker_api.reports.data.common import (
    CLOUD_SCOPE,
    compliance_posture,
    latest_scan_ids,
)
from cloudsneeker_api.reports.data.findings_report import (
    FindingsReportSpec,
    assemble_findings_report,
)
from cloudsneeker_api.reports.schema import ReportData, ReportFilters

SPEC = FindingsReportSpec(
    report_type=CLOUD_POSTURE,
    title="Cloud Posture Report",
    scope=CLOUD_SCOPE,
    noun="cloud findings",
    empty_state=(
        "No completed cloud scans in scope. Connect a cloud account and run a "
        "scan to populate this report."
    ),
)


def assemble(tenant_id: str, filters: ReportFilters) -> ReportData:
    """Assemble the cloud posture report.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters.

    Returns:
        ``ReportData`` with findings, risks, sources, and compliance posture.
    """
    data = assemble_findings_report(tenant_id, filters, SPEC)
    if not data.is_empty:
        data.compliance = compliance_posture(
            tenant_id, latest_scan_ids(tenant_id, filters, CLOUD_SCOPE)
        )
    return data
