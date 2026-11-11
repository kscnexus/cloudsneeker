"""Alert history: one ``AlertEvent`` per rule firing, and its status.

An event is written when a rule matches, before delivery, so a retried
evaluation of the same scan, policy run or day finds the event and does not
notify twice. Status moves between open, acknowledged, resolved and
dismissed by hand; who changed it and when is kept on the event.
"""

from __future__ import annotations

import logging
from typing import Any

from cloudsneeker_api.services.alert_evaluation import RuleMatch
from django.db import IntegrityError, transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

NOTE_MAX_LENGTH = 2000


def event_dedup_key(
    rule_id: Any,
    *,
    trigger: str,
    scan_id: str | None = None,
    custodian_run_id: str | None = None,
    day: str | None = None,
) -> str:
    """One key per rule per scan, per policy run, or per day (daily rules)."""
    if trigger == "daily":
        return f"{rule_id}:daily:{day or timezone.now().date().isoformat()}"
    if custodian_run_id:
        return f"{rule_id}:run:{custodian_run_id}"
    return f"{rule_id}:scan:{scan_id}"


def event_fields(match: RuleMatch) -> dict[str, Any]:
    """Areas, counts and links of a match, as stored on the event."""
    severity_counts: dict[str, int] = {}
    links: list[str] = []
    for area in match.areas:
        for severity, count in (area.severity_counts or {}).items():
            if count:
                severity_counts[severity] = severity_counts.get(severity, 0) + count
        links.extend(link for link in area.links if link not in links)
    return {
        "areas": [area.area for area in match.areas if area.count],
        "area_counts": {area.area: area.count for area in match.areas if area.count},
        "severity_counts": severity_counts,
        "total": match.total,
        "links": links,
    }


def record_event(
    tenant_id: str,
    rule: Any,
    match: RuleMatch,
    *,
    trigger: str,
    scan_id: str | None = None,
    custodian_run_id: str | None = None,
) -> tuple[Any | None, bool]:
    """Create the event of this firing. Returns ``(event, created)``;
    ``created`` is False when the firing was already recorded. On a database
    error the event is ``None`` and ``created`` True, so delivery still runs."""
    from cloudsneeker_api.models import AlertEvent

    key = event_dedup_key(
        rule.id, trigger=trigger, scan_id=scan_id, custodian_run_id=custodian_run_id
    )
    try:
        with transaction.atomic():
            event, created = AlertEvent.objects.get_or_create(
                tenant_id=tenant_id,
                dedup_key=key,
                defaults={
                    "rule": rule,
                    "rule_name": rule.name[:100],
                    "trigger": trigger,
                    "scan_id": scan_id or None,
                    "custodian_run_id": custodian_run_id or None,
                    **event_fields(match),
                },
            )
        return event, created
    except IntegrityError:
        existing = AlertEvent.objects.filter(tenant_id=tenant_id, dedup_key=key).first()
        if existing is not None:
            return existing, False
        logger.exception(
            "Alert event not recorded tenant=%s rule=%s", tenant_id, rule.id
        )
        return None, True
    except Exception:  # noqa: BLE001 - history must never block delivery
        logger.exception(
            "Alert event not recorded tenant=%s rule=%s", tenant_id, rule.id
        )
        return None, True


def mark_delivered(event: Any | None) -> None:
    if event is None:
        return
    try:
        event.delivered = True
        event.save(update_fields=["delivered", "updated_at"])
    except Exception:  # noqa: BLE001
        logger.exception("Alert event delivery flag not saved event=%s", event.id)


def set_status(event: Any, *, status: str, user: Any, note: str | None = None) -> Any:
    """Change an event's status (and note); records who and when."""
    update_fields = ["updated_at"]
    if status != event.status:
        event.status = status
        event.status_changed_at = timezone.now()
        event.status_changed_by = user
        update_fields += ["status", "status_changed_at", "status_changed_by"]
    if note is not None and note != event.note:
        event.note = note
        update_fields.append("note")
    event.save(update_fields=update_fields)
    return event
