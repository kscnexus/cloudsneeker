"""Exceptions report data (RC-003): mute rules and accepted risks.

Lists every exception that takes a finding out of the open counts: upstream
mute rules (``api.MuteRule``) and ``risk_accepted`` triage rows, with who
created or approved them, why, and until when.

Provider visibility: a mute rule has no provider, so when the report is
limited to providers (a limited role always is) a rule is listed only when one
of its finding UIDs belongs to an in-scope provider, and its finding count is
the in-scope UIDs. Triage rows carry their provider and are filtered on it.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from api.models import Finding, MuteRule
from cloudsneeker_api.models import FindingTriage
from cloudsneeker_api.models_appsec import AppSecFinding
from cloudsneeker_api.reports.catalog import EXCEPTIONS
from cloudsneeker_api.reports.data.common import max_detail_rows, provider_label
from cloudsneeker_api.reports.schema import ReportData, ReportFilters, ReportTable
from django.db.models import Count, F
from django.utils import timezone

EXPIRING_DAYS = 30

EMPTY_STATE = (
    "No exceptions in scope: no mute rules and no accepted risks. Findings "
    "that are muted or accepted from a findings list appear here."
)

ACCEPTED_COLUMNS: list[tuple[str, str]] = [
    ("check_id", "Finding"),
    ("area", "Area"),
    ("provider", "Source"),
    ("reason", "Reason"),
    ("approved_by", "Approved by"),
    ("approved_on", "Approved"),
    ("expires_on", "Expires"),
    ("state", "State"),
    ("finding_uid", "Finding UID"),
]

MUTE_RULE_COLUMNS: list[tuple[str, str]] = [
    ("name", "Rule"),
    ("reason", "Reason"),
    ("enabled", "Enabled"),
    ("created_by", "Created by"),
    ("created_on", "Created"),
    ("findings", "Findings"),
]

EXPIRED_COLUMNS: list[tuple[str, str]] = [
    ("check_id", "Finding"),
    ("area", "Area"),
    ("provider", "Source"),
    ("reason", "Reason"),
    ("approved_by", "Approved by"),
    ("expires_on", "Expired on"),
    ("status", "Status now"),
]

AREA_COLUMNS: list[tuple[str, str]] = [
    ("area", "Area"),
    ("accepted", "Accepted risks"),
    ("expiring", f"Expiring in {EXPIRING_DAYS} days"),
    ("expired", "Expired"),
    ("false_positive", "False positives"),
]


def _email(user: Any) -> str:
    return str(getattr(user, "email", "") or "") if user is not None else ""


def _day(value: Any) -> str:
    if value is None:
        return ""
    if hasattr(value, "date") and callable(value.date):
        return value.date().isoformat()
    return value.isoformat()


def acceptance_state(expires_on: date | None, today: date) -> str:
    """``Expired``, ``Expires in N day(s)`` (within 30 days), or ``Active``."""
    if expires_on is None:
        return "Active (no expiry)"
    if expires_on < today:
        return "Expired"
    days = (expires_on - today).days
    if days <= EXPIRING_DAYS:
        return f"Expires in {days} day(s)"
    return "Active"


def _triage_scope(tenant_id: str, filters: ReportFilters):
    queryset = FindingTriage.objects.filter(tenant_id=tenant_id)
    if filters.provider_ids:
        queryset = queryset.filter(provider_id__in=filters.provider_ids)
    return queryset


def _uids_in_scope(tenant_id: str, filters: ReportFilters, uids: list[str]) -> set[str]:
    """UIDs among ``uids`` that belong to a provider in scope."""
    if not uids:
        return set()
    providers = filters.provider_ids
    found = set(
        Finding.all_objects.filter(
            tenant_id=tenant_id, scan__provider_id__in=providers, uid__in=uids
        )
        .values_list("uid", flat=True)
        .distinct()
    )
    found |= set(
        FindingTriage.objects.filter(
            tenant_id=tenant_id, provider_id__in=providers, finding_uid__in=uids
        ).values_list("finding_uid", flat=True)
    )
    found |= set(
        AppSecFinding.objects.filter(
            tenant_id=tenant_id, target__provider_id__in=providers, uid__in=uids
        ).values_list("uid", flat=True)
    )
    return found


def mute_rule_rows(tenant_id: str, filters: ReportFilters) -> list[dict[str, Any]]:
    """Mute rules in scope, enabled first, newest first.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters (``provider_ids`` limits rules to those that
            mute a finding of an in-scope provider).

    Returns:
        Rows keyed by ``MUTE_RULE_COLUMNS`` fields.
    """
    rules = list(
        MuteRule.objects.filter(tenant_id=tenant_id)
        .select_related("created_by")
        .order_by("-enabled", "-inserted_at")
    )
    in_scope: set[str] | None = None
    if filters.provider_ids:
        all_uids = sorted({uid for rule in rules for uid in rule.finding_uids or []})
        in_scope = _uids_in_scope(tenant_id, filters, all_uids)
    rows = []
    for rule in rules:
        uids = list(rule.finding_uids or [])
        if in_scope is not None:
            uids = [uid for uid in uids if uid in in_scope]
            if not uids:
                continue
        rows.append(
            {
                "name": rule.name,
                "reason": rule.reason,
                "enabled": "Yes" if rule.enabled else "No",
                "created_by": _email(rule.created_by) if rule.created_by_id else "",
                "created_on": _day(rule.inserted_at),
                "findings": len(uids),
            }
        )
    return rows


def _triage_row(triage: FindingTriage, areas: dict[str, str]) -> dict[str, Any]:
    return {
        "check_id": triage.check_id or triage.finding_uid,
        "finding_uid": triage.finding_uid,
        "area": areas.get(triage.area, triage.area),
        "provider": provider_label(triage.provider) if triage.provider_id else "",
        "reason": triage.risk_reason,
        "approved_by": (
            _email(triage.risk_approved_by) if triage.risk_approved_by_id else ""
        ),
        "approved_on": _day(triage.risk_approved_at),
        "expires_on": _day(triage.risk_expires_on),
    }


def accepted_risk_rows(
    tenant_id: str, filters: ReportFilters, today: date
) -> list[dict[str, Any]]:
    """Accepted risks in scope, soonest expiry first, with their state."""
    rows = (
        _triage_scope(tenant_id, filters)
        .filter(status=FindingTriage.Status.RISK_ACCEPTED)
        .select_related("risk_approved_by", "provider")
        .order_by(F("risk_expires_on").asc(nulls_last=True), "check_id")
    )
    areas = dict(FindingTriage.Area.choices)
    result = []
    for triage in rows:
        row = _triage_row(triage, areas)
        row["state"] = acceptance_state(triage.risk_expires_on, today)
        row["_area"] = triage.area
        row["_expires_on"] = triage.risk_expires_on
        result.append(row)
    return result


def expired_rows(tenant_id: str, filters: ReportFilters) -> list[dict[str, Any]]:
    """Acceptances the expiry task ended, inside the report's date window."""
    queryset = (
        _triage_scope(tenant_id, filters)
        .filter(risk_expired_at__isnull=False)
        .exclude(status=FindingTriage.Status.RISK_ACCEPTED)
    )
    if filters.date_from:
        queryset = queryset.filter(risk_expired_at__gte=filters.date_from)
    if filters.date_to:
        queryset = queryset.filter(risk_expired_at__lte=filters.date_to)
    areas = dict(FindingTriage.Area.choices)
    statuses = dict(FindingTriage.Status.choices)
    result = []
    for triage in queryset.select_related("risk_approved_by", "provider").order_by(
        "-risk_expired_at"
    ):
        row = _triage_row(triage, areas)
        row["status"] = statuses.get(triage.status, triage.status)
        row["_area"] = triage.area
        result.append(row)
    return result


def _bounded(key: str, title: str, columns, rows: list[dict[str, Any]]) -> ReportTable:
    bound = max_detail_rows()
    return ReportTable(
        key=key,
        title=title,
        columns=columns,
        rows=rows[:bound],
        total=len(rows),
        truncated=len(rows) > bound,
    )


def assemble(tenant_id: str, filters: ReportFilters) -> ReportData:
    """Assemble the exceptions report.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters (providers; the date window bounds the
            expired-acceptance history only; severity does not apply).

    Returns:
        ``ReportData`` with accepted risks, mute rules, expired acceptances
        and a per-area summary. There is no grade.
    """
    data = ReportData(
        report_type=EXCEPTIONS,
        title="Exceptions Report",
        generated_at=timezone.now(),
        filters=filters,
    )
    today = timezone.now().date()
    rules = mute_rule_rows(tenant_id, filters)
    accepted = accepted_risk_rows(tenant_id, filters, today)
    expired_history = expired_rows(tenant_id, filters)
    false_positives = dict(
        _triage_scope(tenant_id, filters)
        .filter(status=FindingTriage.Status.FALSE_POSITIVE)
        .values_list("area")
        .annotate(count=Count("id"))
    )
    if not rules and not accepted and not expired_history:
        data.empty_state = EMPTY_STATE
        data.headline = EMPTY_STATE
        return data

    horizon = today + timedelta(days=EXPIRING_DAYS)
    overdue = [
        row for row in accepted if row["_expires_on"] and row["_expires_on"] < today
    ]
    expiring = [
        row
        for row in accepted
        if row["_expires_on"] and today <= row["_expires_on"] <= horizon
    ]
    active_rules = [row for row in rules if row["enabled"] == "Yes"]
    expired_total = len(overdue) + len(expired_history)
    data.kpis = {
        "mute_rules": len(rules),
        "active_mute_rules": len(active_rules),
        "muted_by_rules": sum(row["findings"] for row in active_rules),
        "accepted_risks": len(accepted),
        "expiring_in_30_days": len(expiring),
        "expired": expired_total,
        "false_positives": sum(false_positives.values()),
    }
    data.headline = (
        f"{len(active_rules)} active mute rule(s) and {len(accepted)} accepted "
        f"risk(s); {len(expiring)} acceptance(s) expire in the next "
        f"{EXPIRING_DAYS} days and {expired_total} have expired."
    )

    by_area = []
    for area, label in FindingTriage.Area.choices:
        by_area.append(
            {
                "area": label,
                "accepted": sum(1 for row in accepted if row["_area"] == area),
                "expiring": sum(1 for row in expiring if row["_area"] == area),
                "expired": sum(1 for row in overdue if row["_area"] == area)
                + sum(1 for row in expired_history if row["_area"] == area),
                "false_positive": int(false_positives.get(area, 0)),
            }
        )

    actions = []
    if overdue:
        actions.append(
            f"Review {len(overdue)} accepted risk(s) past their expiry date: "
            "renew the acceptance with a new approval or fix the finding."
        )
    if expiring:
        actions.append(
            f"Plan the review of {len(expiring)} acceptance(s) expiring in the "
            f"next {EXPIRING_DAYS} days."
        )
    no_reason = sum(1 for row in accepted if not row["reason"])
    if no_reason:
        actions.append(f"Record a reason for {no_reason} accepted risk(s) without one.")
    disabled = len(rules) - len(active_rules)
    if disabled:
        actions.append(f"Delete or re-enable {disabled} disabled mute rule(s).")
    data.remediation = [
        {"priority": index, "action": action}
        for index, action in enumerate(actions, start=1)
    ]

    for row in accepted + expired_history:
        row.pop("_area", None)
        row.pop("_expires_on", None)
    data.tables = [
        _bounded("accepted_risks", "Accepted risks", ACCEPTED_COLUMNS, accepted),
        _bounded("mute_rules", "Mute rules", MUTE_RULE_COLUMNS, rules),
        _bounded(
            "expired_acceptances",
            "Expired acceptances",
            EXPIRED_COLUMNS,
            expired_history,
        ),
        ReportTable(
            key="by_area",
            title="Exceptions by area",
            columns=AREA_COLUMNS,
            rows=by_area,
            total=len(by_area),
        ),
    ]
    return data
