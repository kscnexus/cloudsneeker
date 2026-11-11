"""Remediation tracking report data.

Application Security findings (``AppSecFinding``) carry a lifecycle (new,
open, reopened, fixed), a priority, a due date from the SLA settings, and
fix timestamps. Triage rows (``FindingTriage``) carry the workflow status of
findings in every area. This report reads both:

* open findings by priority and overdue findings (due date passed, not
  fixed, not suppressed, not closed in triage);
* findings fixed in the period and their mean time to remediate
  (``fixed_at - first_seen_at``);
* reopened findings;
* triage status distribution per area.

The period is the report's date window; without one it is the last 30 days.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from cloudsneeker_api.appsec.queries import (
    ACTIVE_STATES,
    CLOSED_TRIAGE,
    findings_queryset,
)
from cloudsneeker_api.models import FindingTriage
from cloudsneeker_api.models_appsec import AppSecFinding
from cloudsneeker_api.reports.catalog import REMEDIATION
from cloudsneeker_api.reports.data.common import max_detail_rows
from cloudsneeker_api.reports.schema import ReportData, ReportFilters, ReportTable
from django.db.models import Count, Q, QuerySet
from django.utils import timezone

DEFAULT_PERIOD_DAYS = 30
PRIORITIES: tuple[str, ...] = tuple(
    value for value, _ in AppSecFinding.Priority.choices
)

EMPTY_STATE = (
    "Nothing to track yet: no application security findings and no triaged "
    "findings in scope. Run an Application Security scan or triage findings to "
    "populate this report."
)

PRIORITY_COLUMNS: list[tuple[str, str]] = [
    ("priority", "Priority"),
    ("open", "Open"),
    ("overdue", "Overdue"),
    ("reopened", "Reopened"),
]

OVERDUE_COLUMNS: list[tuple[str, str]] = [
    ("priority", "Priority"),
    ("severity", "Severity"),
    ("title", "Finding"),
    ("target", "Target"),
    ("due_at", "Due"),
    ("days_overdue", "Days overdue"),
    ("state", "State"),
    ("triage_status", "Triage"),
]

FIXED_COLUMNS: list[tuple[str, str]] = [
    ("severity", "Severity"),
    ("title", "Finding"),
    ("target", "Target"),
    ("first_seen_at", "First seen"),
    ("fixed_at", "Fixed"),
    ("days_to_fix", "Days to fix"),
]

TRIAGE_STATUSES: tuple[str, ...] = tuple(
    value for value, _ in FindingTriage.Status.choices
)
TRIAGE_COLUMNS: list[tuple[str, str]] = [
    ("area", "Area"),
    *[(status, label) for status, label in FindingTriage.Status.choices],
    ("total", "Total"),
]


def _day(value: Any) -> str:
    return value.date().isoformat() if value else ""


def report_period(filters: ReportFilters, now):
    """Return ``(start, end)``: the date window or the last 30 days."""
    end = filters.date_to or now
    start = filters.date_from or end - timedelta(days=DEFAULT_PERIOD_DAYS)
    return start, end


def scoped_findings(tenant_id: str, filters: ReportFilters) -> QuerySet:
    """Application findings of the providers in scope, severity floor applied."""
    queryset = findings_queryset(tenant_id, set(filters.provider_ids) or None)
    if filters.severity_floor:
        queryset = queryset.filter(severity__in=filters.severities())
    return queryset


def triage_by_area(tenant_id: str, filters: ReportFilters) -> list[dict[str, Any]]:
    """Triage status counts per area (one row per area, every status)."""
    queryset = FindingTriage.objects.filter(tenant_id=tenant_id)
    if filters.provider_ids:
        queryset = queryset.filter(provider_id__in=filters.provider_ids)
    counts: dict[str, dict[str, int]] = {}
    for row in queryset.values("area", "status").annotate(count=Count("id")):
        counts.setdefault(row["area"], {})[row["status"]] = int(row["count"] or 0)
    rows = []
    for area, label in FindingTriage.Area.choices:
        bucket = counts.get(area, {})
        row: dict[str, Any] = {"area": label}
        for status in TRIAGE_STATUSES:
            row[status] = bucket.get(status, 0)
        row["total"] = sum(bucket.values())
        rows.append(row)
    return rows


def _overdue_rows(overdue: QuerySet, now) -> tuple[list[dict[str, Any]], int]:
    total = overdue.count()
    rows = []
    for item in overdue.select_related("target").order_by("due_at", "-severity_rank")[
        : max_detail_rows()
    ]:
        rows.append(
            {
                "priority": item.priority,
                "severity": item.severity,
                "title": item.title,
                "target": item.target.name,
                "due_at": _day(item.due_at),
                "days_overdue": max(0, (now - item.due_at).days),
                "state": item.state,
                "triage_status": item.triage_status,
            }
        )
    return rows, total


def _fixed_rows(fixed: QuerySet) -> tuple[list[dict[str, Any]], int, float | None]:
    durations = []
    rows = []
    bound = max_detail_rows()
    total = 0
    for item in (
        fixed.select_related("target").order_by("-fixed_at").iterator(chunk_size=2000)
    ):
        total += 1
        days = max(0.0, (item.fixed_at - item.first_seen_at).total_seconds() / 86400)
        durations.append(days)
        if len(rows) < bound:
            rows.append(
                {
                    "severity": item.severity,
                    "title": item.title,
                    "target": item.target.name,
                    "first_seen_at": _day(item.first_seen_at),
                    "fixed_at": _day(item.fixed_at),
                    "days_to_fix": round(days, 1),
                }
            )
    mean = round(sum(durations) / len(durations), 1) if durations else None
    return rows, total, mean


def assemble(tenant_id: str, filters: ReportFilters) -> ReportData:
    """Assemble the remediation tracking report.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters (providers, severity floor, period).

    Returns:
        ``ReportData`` with lifecycle KPIs, overdue and fixed tables and the
        triage distribution per area. There is no grade.
    """
    now = timezone.now()
    data = ReportData(
        report_type=REMEDIATION,
        title="Remediation Tracking Report",
        generated_at=now,
        filters=filters,
    )
    findings = scoped_findings(tenant_id, filters)
    triage_rows = triage_by_area(tenant_id, filters)
    triaged = sum(row["total"] for row in triage_rows)
    if not findings.exists() and not triaged:
        data.empty_state = EMPTY_STATE
        data.headline = EMPTY_STATE
        return data

    start, end = report_period(filters, now)
    active = findings.filter(state__in=ACTIVE_STATES, suppressed=False)
    overdue = active.filter(due_at__lt=now).exclude(triage_status__in=CLOSED_TRIAGE)
    fixed = findings.filter(
        state=AppSecFinding.State.FIXED,
        fixed_at__gte=start,
        fixed_at__lte=end,
    )

    by_priority: dict[str, dict[str, int]] = {
        priority: {"open": 0, "overdue": 0, "reopened": 0} for priority in PRIORITIES
    }
    for row in active.values("priority").annotate(
        open=Count("id"),
        overdue=Count(
            "id",
            filter=Q(due_at__lt=now) & ~Q(triage_status__in=CLOSED_TRIAGE),
        ),
        reopened=Count("id", filter=Q(state=AppSecFinding.State.REOPENED)),
    ):
        bucket = by_priority.setdefault(
            row["priority"], {"open": 0, "overdue": 0, "reopened": 0}
        )
        bucket["open"] += int(row["open"] or 0)
        bucket["overdue"] += int(row["overdue"] or 0)
        bucket["reopened"] += int(row["reopened"] or 0)
    priority_rows = [
        {"priority": priority, **counts} for priority, counts in by_priority.items()
    ]

    for row in active.values("severity").annotate(count=Count("id")):
        if row["severity"] in data.severity_totals:
            data.severity_totals[row["severity"]] = int(row["count"] or 0)

    overdue_rows, overdue_total = _overdue_rows(overdue, now)
    fixed_rows, fixed_total, mttr = _fixed_rows(fixed)
    open_total = sum(row["open"] for row in priority_rows)
    reopened_total = sum(row["reopened"] for row in priority_rows)
    ever_reopened = findings.filter(reopen_count__gt=0).count()

    data.kpis = {
        "open_findings": open_total,
        "open_urgent": by_priority.get("urgent", {}).get("open", 0),
        "open_high_priority": by_priority.get("high", {}).get("open", 0),
        "overdue": overdue_total,
        "fixed_in_period": fixed_total,
        "mean_days_to_remediate": mttr,
        "reopened_open": reopened_total,
        "reopened_ever": ever_reopened,
        "triaged_findings": triaged,
        "period_start": start.date().isoformat(),
        "period_end": end.date().isoformat(),
    }
    mttr_text = f"{mttr} days" if mttr is not None else "not available"
    data.headline = (
        f"{open_total} open application finding(s), {overdue_total} overdue; "
        f"{fixed_total} fixed between {start.date().isoformat()} and "
        f"{end.date().isoformat()} (mean time to remediate {mttr_text}); "
        f"{reopened_total} reopened."
    )
    actions = []
    urgent_overdue = by_priority.get("urgent", {}).get("overdue", 0)
    if urgent_overdue:
        actions.append(f"Fix the {urgent_overdue} overdue urgent finding(s) first.")
    if overdue_total:
        oldest = overdue_rows[0]["due_at"] if overdue_rows else ""
        actions.append(
            f"Assign owners to {overdue_total} overdue finding(s); the oldest "
            f"was due on {oldest}."
        )
    if reopened_total:
        actions.append(
            f"Find why {reopened_total} finding(s) came back after a fix and "
            "add a regression check."
        )
    if not actions and open_total:
        actions.append("Keep fixing open findings before their due dates.")
    data.remediation = [
        {"priority": index, "action": action}
        for index, action in enumerate(actions, start=1)
    ]

    data.tables = [
        ReportTable(
            key="by_priority",
            title="Open findings by priority",
            columns=PRIORITY_COLUMNS,
            rows=priority_rows,
            total=len(priority_rows),
        ),
        ReportTable(
            key="findings",
            title="Overdue findings",
            columns=OVERDUE_COLUMNS,
            rows=overdue_rows,
            total=overdue_total,
            truncated=len(overdue_rows) < overdue_total,
        ),
        ReportTable(
            key="fixed",
            title="Fixed in the period",
            columns=FIXED_COLUMNS,
            rows=fixed_rows,
            total=fixed_total,
            truncated=len(fixed_rows) < fixed_total,
        ),
        ReportTable(
            key="triage_by_area",
            title="Triage status by area",
            columns=TRIAGE_COLUMNS,
            rows=triage_rows,
            total=len(triage_rows),
        ),
    ]
    return data
