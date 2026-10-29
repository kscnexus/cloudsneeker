"""Generic findings report used by the cloud and application security types."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Iterable

from cloudsneeker_api.reports.data.common import (
    FINDING_COLUMNS,
    ScanScope,
    aggregate_findings,
    breakdown_by_scan,
    breakdown_by_service,
    findings_for,
    findings_table,
    grade_for,
    latest_scan_ids,
    remediation_priorities,
    risk_table,
    scan_streams,
    security_score,
    severity_kpis,
    top_risks,
    trend,
)
from cloudsneeker_api.reports.schema import ReportData, ReportFilters
from django.db.models import Q
from django.utils import timezone


@dataclass
class FindingsReportSpec:
    """How one findings-based report reads and labels its data.

    Attributes:
        report_type: Catalog key.
        title: Cover title.
        scope: Scans to read.
        noun: Plural noun used in the headline ("cloud findings").
        empty_state: Message when no scan is in scope.
        include_q: Extra finding condition.
        exclude_q: Finding exclusions.
        detail_title: Title of the findings table.
        columns: Findings table columns.
        row_builder: Custom row builder for the findings table.
    """

    report_type: str
    title: str
    scope: ScanScope
    noun: str
    empty_state: str
    include_q: Q | None = None
    exclude_q: Iterable[Q] = field(default_factory=tuple)
    detail_title: str = "Failed findings"
    columns: list[tuple[str, str]] = field(default_factory=lambda: list(FINDING_COLUMNS))
    row_builder: Callable[[dict[str, Any], dict[str, str]], dict[str, Any]] | None = None


def headline_for(noun: str, stats_fail: int, critical: int, high: int, grade: str) -> str:
    """Return the one-sentence summary of a findings report."""
    if stats_fail == 0:
        return f"No open {noun} in scope. Grade {grade}."
    urgent = critical + high
    if urgent:
        return (
            f"{stats_fail} open {noun}, {urgent} of them critical or high "
            f"({critical} critical). Grade {grade}."
        )
    return f"{stats_fail} open {noun}, none critical or high. Grade {grade}."


def assemble_findings_report(
    tenant_id: str, filters: ReportFilters, spec: FindingsReportSpec
) -> ReportData:
    """Assemble a findings report from the latest scans in ``spec.scope``.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters.
        spec: Report specification.

    Returns:
        ``ReportData`` (``empty_state`` set when no scan is in scope).
    """
    data = ReportData(
        report_type=spec.report_type,
        title=spec.title,
        generated_at=timezone.now(),
        filters=filters,
    )
    scan_ids = latest_scan_ids(tenant_id, filters, spec.scope)
    if not scan_ids:
        data.empty_state = spec.empty_state
        data.headline = spec.empty_state
        return data

    queryset = findings_for(
        tenant_id,
        scan_ids,
        filters,
        include_q=spec.include_q,
        exclude_q=spec.exclude_q,
    )
    stats = aggregate_findings(queryset)
    data.severity_totals = dict(stats.fail_by_severity)
    data.status_totals = dict(stats.status)
    data.score = security_score(stats.fail_by_severity, stats.pass_by_severity)
    data.grade = grade_for(data.score)
    streams = scan_streams(scan_ids)
    data.kpis = {
        **severity_kpis(stats),
        "scans_in_scope": len(scan_ids),
        "providers_in_scope": len({stream["provider_id"] for stream in streams}),
    }
    data.headline = headline_for(
        spec.noun,
        stats.status["fail"],
        stats.fail_by_severity["critical"],
        stats.fail_by_severity["high"],
        data.grade,
    )
    data.sources = breakdown_by_scan(queryset, streams)
    data.extra["services"] = breakdown_by_service(queryset)
    data.trend = trend(
        tenant_id,
        filters,
        spec.scope,
        extra_q=spec.include_q,
        exclude_q=spec.exclude_q,
    )
    data.top_risks = top_risks(queryset, limit=10)
    data.remediation = remediation_priorities(data.top_risks)
    data.tables = [
        risk_table(data.top_risks),
        findings_table(
            "findings",
            spec.detail_title,
            queryset,
            columns=spec.columns,
            row_builder=spec.row_builder,
        ),
    ]
    return data
