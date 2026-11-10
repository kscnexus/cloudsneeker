"""Risk priority and remediation due dates of Application Security findings.

Priority is not severity. It raises a finding when it is known to be
exploited (CISA KEV), likely to be exploited (EPSS) or an exposed secret:

* ``p0`` Immediate: a known exploited CVE rated critical or high, or a
  critical secret.
* ``p1`` Urgent: any other critical finding, any known exploited CVE, a high
  CVE with an EPSS score of at least ``EPSS_URGENT``, or a high secret.
* ``p2`` High: any other high finding.
* ``p3`` Normal: medium.
* ``p4`` Low: low and informational.

Each priority has a remediation window (``PRIORITY_SLA_DAYS``) counted from
when the finding was first seen. A finding is overdue once the window has
passed while its triage status is still active (``ACTIVE_TRIAGE_STATUSES``).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from functools import reduce
from operator import or_

from cloudsneeker_api.models import FindingTriage, VulnerabilityIntel
from cloudsneeker_api.services.app_security_categories import SECURITY_CATEGORY
from django.db.models import (
    Case,
    CharField,
    Exists,
    OuterRef,
    Q,
    Value,
    When,
)


class PRIORITY:  # noqa: N801 - mirrors the UI constant object
    P0 = "p0"
    P1 = "p1"
    P2 = "p2"
    P3 = "p3"
    P4 = "p4"


PRIORITIES = (PRIORITY.P0, PRIORITY.P1, PRIORITY.P2, PRIORITY.P3, PRIORITY.P4)
EPSS_URGENT = 0.1
PRIORITY_SLA_DAYS = {
    PRIORITY.P0: 2,
    PRIORITY.P1: 7,
    PRIORITY.P2: 30,
    PRIORITY.P3: 90,
    PRIORITY.P4: 180,
}
STATUS = FindingTriage.Status
ACTIVE_TRIAGE_STATUSES = (
    STATUS.OPEN,
    STATUS.UNDER_REVIEW,
    STATUS.REMEDIATING,
    STATUS.REOPENED,
)

_URGENT_SEVERITIES = ("critical", "high")


def priority(
    severity: str,
    category: str,
    *,
    known_exploited: bool = False,
    epss_score: float | None = None,
) -> str:
    """The priority of one finding (see the module docstring)."""
    severity = (severity or "").lower()
    secret = category == SECURITY_CATEGORY.SECRETS
    if (known_exploited and severity in _URGENT_SEVERITIES) or (
        secret and severity == "critical"
    ):
        return PRIORITY.P0
    if (
        severity == "critical"
        or known_exploited
        or (severity == "high" and secret)
        or (severity == "high" and (epss_score or 0) >= EPSS_URGENT)
    ):
        return PRIORITY.P1
    if severity == "high":
        return PRIORITY.P2
    if severity == "medium":
        return PRIORITY.P3
    return PRIORITY.P4


def due_at(first_seen_at: datetime | None, priority_value: str) -> datetime | None:
    if first_seen_at is None:
        return None
    return first_seen_at + timedelta(days=PRIORITY_SLA_DAYS[priority_value])


def is_overdue(
    first_seen_at: datetime | None,
    priority_value: str,
    triage_status: str,
    now: datetime,
) -> bool:
    due = due_at(first_seen_at, priority_value)
    return bool(due and due < now and triage_status in ACTIVE_TRIAGE_STATUSES)


def known_exploited_annotation() -> Exists:
    """True when the row's ``check_id`` is in the KEV catalog."""
    return Exists(
        VulnerabilityIntel.objects.filter(kev=True, cve_id=OuterRef("check_id"))
    )


def priority_case() -> Case:
    """Database form of :func:`priority`.

    Needs the ``cs_category``, ``cs_kev`` and ``cs_epss`` annotations.
    """
    urgent = Q(severity__in=_URGENT_SEVERITIES)
    secret = Q(cs_category=SECURITY_CATEGORY.SECRETS)
    return Case(
        When(
            (Q(cs_kev=True) & urgent) | (secret & Q(severity="critical")),
            then=Value(PRIORITY.P0),
        ),
        When(
            Q(severity="critical")
            | Q(cs_kev=True)
            | (Q(severity="high") & secret)
            | (Q(severity="high") & Q(cs_epss__gte=EPSS_URGENT)),
            then=Value(PRIORITY.P1),
        ),
        When(severity="high", then=Value(PRIORITY.P2)),
        When(severity="medium", then=Value(PRIORITY.P3)),
        default=Value(PRIORITY.P4),
        output_field=CharField(),
    )


def past_sla_q(now: datetime) -> Q:
    """Rows whose remediation window has passed (needs ``cs_priority``)."""
    return reduce(
        or_,
        (
            Q(cs_priority=value, first_seen_at__lt=now - timedelta(days=days))
            for value, days in PRIORITY_SLA_DAYS.items()
        ),
    )
