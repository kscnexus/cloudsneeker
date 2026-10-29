"""Infrastructure as Code report data."""

from __future__ import annotations

from cloudsneeker_api.reports.catalog import IAC
from cloudsneeker_api.reports.data.common import SECRET_Q, VULNERABILITY_Q, ScanScope
from cloudsneeker_api.reports.data.findings_report import (
    FindingsReportSpec,
    assemble_findings_report,
)
from cloudsneeker_api.reports.schema import ReportData, ReportFilters

SCOPE = ScanScope(
    trivy_modes=frozenset({"iac", "repo", "fs"}),
    prowler_provider_types=frozenset({"iac"}),
)

SPEC = FindingsReportSpec(
    report_type=IAC,
    title="Infrastructure as Code Report",
    scope=SCOPE,
    noun="IaC misconfigurations",
    empty_state=(
        "No Infrastructure as Code scans in scope. Connect a repository and "
        "run an IaC scan to populate this report."
    ),
    # Misconfigurations only: vulnerabilities and secrets have their own reports.
    exclude_q=(VULNERABILITY_Q, SECRET_Q),
    detail_title="Misconfigurations",
)


def assemble(tenant_id: str, filters: ReportFilters) -> ReportData:
    """Assemble the IaC report.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters.

    Returns:
        ``ReportData`` limited to misconfiguration findings.
    """
    return assemble_findings_report(tenant_id, filters, SPEC)
