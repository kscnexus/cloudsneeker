"""Container image report data."""

from __future__ import annotations

from cloudsneeker_api.reports.catalog import CONTAINER
from cloudsneeker_api.reports.data.common import (
    SECRET_Q,
    VULNERABILITY_Q,
    ScanScope,
    aggregate_findings,
    failing_condition,
    findings_for,
    latest_scan_ids,
    scoped_stats,
)
from cloudsneeker_api.reports.data.findings_report import (
    FindingsReportSpec,
    assemble_findings_report,
)
from cloudsneeker_api.reports.schema import ReportData, ReportFilters

SCOPE = ScanScope(
    trivy_modes=frozenset({"image", "k8s"}),
    prowler_provider_types=frozenset({"image"}),
)

SPEC = FindingsReportSpec(
    report_type=CONTAINER,
    title="Container Image Report",
    scope=SCOPE,
    noun="container image findings",
    empty_state=(
        "No container image scans in scope. Add an image or Kubernetes target "
        "in Application Security to populate this report."
    ),
    detail_title="Container image findings",
)


def assemble(tenant_id: str, filters: ReportFilters) -> ReportData:
    """Assemble the container image report.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters.

    Returns:
        ``ReportData`` with a vulnerability / secret / misconfiguration split.
    """
    data = assemble_findings_report(tenant_id, filters, SPEC)
    if data.is_empty:
        return data
    scan_ids = latest_scan_ids(tenant_id, filters, SCOPE)

    def _stats(include_q):
        queryset = findings_for(tenant_id, scan_ids, filters, include_q=include_q)
        if not filters.status_scope:
            return aggregate_findings(queryset)
        return scoped_stats(
            queryset, failing_condition(tenant_id, filters.status_scope)
        )

    vulns = _stats(VULNERABILITY_Q)
    secrets = _stats(SECRET_Q)
    data.kpis["vulnerabilities"] = vulns.status["fail"]
    data.kpis["secrets"] = secrets.status["fail"]
    data.kpis["misconfigurations"] = max(
        0, data.status_totals["fail"] - vulns.status["fail"] - secrets.status["fail"]
    )
    data.kpis["images_in_scope"] = len(scan_ids)
    return data
