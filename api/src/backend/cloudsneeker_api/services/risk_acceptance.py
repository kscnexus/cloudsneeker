"""Expiry of accepted risks (EB-019).

An hourly Celery Beat task (``cloudsneeker-expire-risk-acceptances``) finds
``risk_accepted`` triage rows whose ``risk_expires_on`` is before today
(UTC), across every tenant, and for each one:

* sets the status to ``reopened`` with ``source=automation`` and records
  ``risk_expired_at``;
* adds a note to the thread saying when the acceptance expired;
* emails the finding owner (the assignee, else the approver) through the
  tenant's own SMTP settings, one message per tenant and recipient.

The acceptance reason, approver and expiry date stay on the row as history.
A finding the inherited cloud UI muted when the risk was accepted stays
muted; the note and email say so, because the mute rule is upstream data the
user removes on the Mutelist page.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime
from smtplib import SMTPException

from api.db_router import MainRouter
from api.models import Finding
from cloudsneeker_api.brand import brand
from cloudsneeker_api.models import FindingTriage, FindingTriageNote
from django.conf import settings
from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

TRIAGE_PATHS = {
    FindingTriage.Area.CLOUD: "/triage",
    FindingTriage.Area.APPLICATION_SECURITY: "/application-security/triage",
    FindingTriage.Area.GOVERNANCE: "/governance/triage",
}
MAX_FINDINGS_IN_EMAIL = 50


@dataclass(frozen=True)
class ExpiredRisk:
    tenant_id: str
    finding_uid: str
    check_id: str
    area: str
    expired_on: date
    reason: str
    owner_email: str
    muted: bool


def expiry_note(expires_on: date, muted: bool) -> str:
    """Note added to the thread when the expiry task reopens a finding."""
    note = (
        f"Risk acceptance expired on {expires_on.isoformat()}. "
        "The finding is open again for review."
    )
    if muted:
        note += (
            " It is still muted by a mute rule; remove the rule on the Mutelist "
            "page to see it in finding lists again."
        )
    return note


def _owner_email(triage: FindingTriage) -> str:
    for user in (triage.assignee, triage.risk_approved_by):
        email = getattr(user, "email", "") if user else ""
        if email:
            return email
    return ""


def _muted_uids(db: str, tenant_ids: set[str], uids: set[str]) -> set[str]:
    """UIDs whose latest finding row is muted (cloud and AppSec findings)."""
    if not uids:
        return set()
    rows = (
        Finding.all_objects.using(db)
        .filter(tenant_id__in=list(tenant_ids), uid__in=list(uids))
        .order_by("tenant_id", "uid", "-inserted_at")
        .distinct("tenant_id", "uid")
        .values_list("uid", "muted")
    )
    return {uid for uid, muted in rows if muted}


def expire_risk_acceptances(now: datetime | None = None) -> list[ExpiredRisk]:
    """Reopen every risk acceptance that expired before today.

    Runs on the admin connection because it spans tenants.
    """
    now = now or timezone.now()
    today = now.date()
    db = MainRouter.admin_db
    due = list(
        FindingTriage.objects.using(db)
        .filter(
            status=FindingTriage.Status.RISK_ACCEPTED,
            risk_expires_on__lt=today,
        )
        .select_related("assignee", "risk_approved_by")
        .order_by("tenant_id", "risk_expires_on")
    )
    if not due:
        return []
    muted = _muted_uids(
        db,
        {str(triage.tenant_id) for triage in due},
        {triage.finding_uid for triage in due},
    )
    expired: list[ExpiredRisk] = []
    for triage in due:
        is_muted = triage.finding_uid in muted
        with transaction.atomic(using=db):
            updated = (
                FindingTriage.objects.using(db)
                .filter(pk=triage.pk, status=FindingTriage.Status.RISK_ACCEPTED)
                .update(
                    status=FindingTriage.Status.REOPENED,
                    status_changed_at=now,
                    source=FindingTriage.Source.AUTOMATION,
                    risk_expired_at=now,
                    updated_by=None,
                    updated_at=now,
                )
            )
            if not updated:
                continue
            FindingTriageNote.objects.using(db).create(
                tenant_id=triage.tenant_id,
                triage_id=triage.pk,
                author=None,
                body=expiry_note(triage.risk_expires_on, is_muted),
                status=FindingTriage.Status.REOPENED,
            )
        expired.append(
            ExpiredRisk(
                tenant_id=str(triage.tenant_id),
                finding_uid=triage.finding_uid,
                check_id=triage.check_id,
                area=triage.area,
                expired_on=triage.risk_expires_on,
                reason=triage.risk_reason,
                owner_email=_owner_email(triage),
                muted=is_muted,
            )
        )
    return expired


def expiry_email(risks: list[ExpiredRisk]) -> tuple[str, str]:
    """Subject and plain-text body for one owner's expired risks."""
    count = len(risks)
    subject = f"{brand.name}: {count} accepted risk{'s' if count != 1 else ''} expired"
    base = (getattr(settings, "UI_BASE_URL", "") or "").rstrip("/")
    lines = [
        f"{count} risk acceptance{'s' if count != 1 else ''} expired and the "
        "findings are open again for review:",
        "",
    ]
    for risk in risks[:MAX_FINDINGS_IN_EMAIL]:
        line = f"- {risk.check_id or risk.finding_uid} (expired {risk.expired_on})"
        if risk.reason:
            line += f": {risk.reason[:200]}"
        if risk.muted:
            line += " [still muted]"
        lines.append(line)
    if count > MAX_FINDINGS_IN_EMAIL:
        lines.append(f"- and {count - MAX_FINDINGS_IN_EMAIL} more")
    areas = sorted({risk.area for risk in risks})
    if base:
        lines += ["", "Review them on the Triage page:"]
        lines += [f"{base}{TRIAGE_PATHS.get(area, '/triage')}" for area in areas]
    lines += [
        "",
        "Fix the finding, or accept the risk again with a new reason and expiry.",
    ]
    return subject, "\n".join(lines)


def notify_owners(risks: list[ExpiredRisk]) -> int:
    """Email each owner once per tenant; returns the number of emails sent.

    Tenants without SMTP settings, and findings without an owner email, are
    skipped (the note on the thread still records the expiry).
    """
    from cloudsneeker_api.services.email_delivery import send_with_tenant_smtp

    grouped: dict[tuple[str, str], list[ExpiredRisk]] = defaultdict(list)
    for risk in risks:
        if risk.owner_email:
            grouped[(risk.tenant_id, risk.owner_email)].append(risk)
    sent = 0
    for (tenant_id, email), owner_risks in grouped.items():
        subject, body = expiry_email(owner_risks)
        try:
            sent += bool(
                send_with_tenant_smtp(
                    tenant_id=tenant_id,
                    subject=subject,
                    message=body,
                    recipient_list=[email],
                )
            )
        except (ValueError, SMTPException, OSError) as error:
            logger.info(
                "Risk expiry email not sent for tenant %s: %s", tenant_id, error
            )
    return sent
