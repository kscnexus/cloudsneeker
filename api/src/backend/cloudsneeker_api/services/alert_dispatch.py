"""Run alert rules for a finished scan or on the daily schedule and notify."""

from __future__ import annotations

import logging
from typing import Any

from cloudsneeker_api.services.alert_evaluation import (
    RuleMatch,
    alertable_findings,
    evaluate_finding_rule,
    evaluate_governance_rule,
    latest_scan_ids,
    merge_matches,
    notification_body,
)

logger = logging.getLogger(__name__)

TRIGGER_AFTER_SCAN = "after_scan"
TRIGGER_DAILY = "daily"


def _rule_triggers(trigger: str) -> list[str]:
    from cloudsneeker_api.models import AlertRule

    if trigger == TRIGGER_DAILY:
        return [AlertRule.Trigger.DAILY, AlertRule.Trigger.BOTH]
    return [AlertRule.Trigger.AFTER_SCAN, AlertRule.Trigger.BOTH]


def tenants_with_daily_rules() -> list[str]:
    """Tenants with at least one enabled daily rule (admin connection)."""
    from api.db_router import MainRouter
    from cloudsneeker_api.models import AlertRule

    return [
        str(pk)
        for pk in AlertRule.objects.using(MainRouter.admin_db)
        .filter(enabled=True, trigger__in=_rule_triggers(TRIGGER_DAILY))
        .values_list("tenant_id", flat=True)
        .distinct()
    ]


def _governance_findings(
    tenant_id: str, custodian_run_id: str | None
) -> list[Any]:
    """Findings of one policy run, or of the latest run of every policy."""
    from cloudsneeker_api.models import CustodianRun
    from cloudsneeker_api.services.governance_findings import (
        _first_seen,
        findings_for_run,
    )

    runs = CustodianRun.objects.filter(
        tenant_id=tenant_id, status=CustodianRun.Status.COMPLETED
    ).select_related("policy")
    if custodian_run_id:
        runs = list(runs.filter(id=custodian_run_id))
    else:
        runs = list(
            runs.order_by("policy_id", "-finished_at", "-inserted_at").distinct(
                "policy_id"
            )
        )
    first_seen = _first_seen(tenant_id, [str(run.policy_id) for run in runs])
    findings: list[Any] = []
    for run in runs:
        findings.extend(
            findings_for_run(run, run.policy, first_seen.get(str(run.policy_id)))
        )
    return findings


def _provider_types(tenant_id: str) -> dict[str, str]:
    from api.models import Provider

    return {
        str(row["id"]): row["provider"]
        for row in Provider.objects.filter(tenant_id=tenant_id).values(
            "id", "provider"
        )
    }


def _notify(tenant_id: str, rule: Any, match: RuleMatch) -> bool:
    from cloudsneeker_api.models import AlertRecipient
    from cloudsneeker_api.services.email_delivery import send_with_tenant_smtp
    from cloudsneeker_api.services.slack import post_alert_to_channels

    body = notification_body(rule.name, rule.description or "", match)
    subject = f"[Cloudsneeker] {rule.name}"
    emails = list(
        rule.recipients.filter(status=AlertRecipient.Status.CONFIRMED).values_list(
            "email", flat=True
        )
    )
    if emails:
        try:
            send_with_tenant_smtp(
                tenant_id=tenant_id,
                subject=subject,
                message=body,
                recipient_list=emails,
            )
        except Exception:
            logger.exception(
                "Alert email delivery failed tenant=%s rule=%s", tenant_id, rule.id
            )
    channel_ids = list(rule.slack_channel_ids or [])
    if channel_ids:
        try:
            post_alert_to_channels(
                tenant_id=tenant_id,
                channel_ids=channel_ids,
                text=f"*{subject}*\n{body}",
            )
        except Exception:
            logger.exception(
                "Alert Slack delivery failed tenant=%s rule=%s", tenant_id, rule.id
            )
    return bool(emails or channel_ids)


def evaluate_rules(
    tenant_id: str,
    *,
    scan_id: str | None = None,
    custodian_run_id: str | None = None,
    trigger: str = TRIGGER_AFTER_SCAN,
) -> list[tuple[Any, RuleMatch]]:
    """Matches of every enabled rule for this event (no delivery)."""
    from cloudsneeker_api.models import AlertRule

    rules = list(
        AlertRule.objects.filter(
            tenant_id=tenant_id, enabled=True, trigger__in=_rule_triggers(trigger)
        ).prefetch_related("recipients")
    )
    if not rules:
        return []

    finding_rows = None
    if trigger == TRIGGER_DAILY:
        finding_rows = alertable_findings(tenant_id).filter(
            scan_id__in=latest_scan_ids(tenant_id)
        )
    elif scan_id:
        finding_rows = alertable_findings(tenant_id).filter(scan_id=scan_id)

    governance = None
    if trigger == TRIGGER_DAILY or custodian_run_id:
        governance = _governance_findings(tenant_id, custodian_run_id)
    provider_types = _provider_types(tenant_id) if governance else {}

    results: list[tuple[Any, RuleMatch]] = []
    for rule in rules:
        condition = rule.condition or {}
        parts: list[RuleMatch] = []
        if finding_rows is not None:
            parts.append(evaluate_finding_rule(tenant_id, finding_rows, condition))
        if governance is not None:
            parts.append(evaluate_governance_rule(governance, condition, provider_types))
        match = merge_matches(*parts) if parts else RuleMatch(matched=False)
        if match.matched:
            results.append((rule, match))
    return results


def evaluate_and_notify(
    tenant_id: str,
    *,
    scan_id: str | None = None,
    custodian_run_id: str | None = None,
    trigger: str = TRIGGER_AFTER_SCAN,
) -> dict[str, int]:
    from api.db_utils import rls_transaction
    from cloudsneeker_api.services.alert_events import mark_delivered, record_event

    notified = 0
    already_recorded = 0
    with rls_transaction(tenant_id):
        matches = evaluate_rules(
            tenant_id,
            scan_id=scan_id,
            custodian_run_id=custodian_run_id,
            trigger=trigger,
        )
        for rule, match in matches:
            # The event is written first: a retried evaluation finds it and
            # does not notify the same firing twice.
            event, created = record_event(
                tenant_id,
                rule,
                match,
                trigger=TRIGGER_DAILY if trigger == TRIGGER_DAILY else TRIGGER_AFTER_SCAN,
                scan_id=scan_id,
                custodian_run_id=custodian_run_id,
            )
            if not created:
                already_recorded += 1
                continue
            if _notify(tenant_id, rule, match):
                notified += 1
                mark_delivered(event)
    return {
        "rules_matched": len(matches),
        "rules_notified": notified,
        "already_recorded": already_recorded,
    }


def enqueue_after_scan(
    tenant_id: str,
    *,
    scan_id: str | None = None,
    custodian_run_id: str | None = None,
    using: str | None = None,
) -> None:
    """Queue after-scan evaluation once the current transaction commits."""
    from django.db import transaction

    def _send() -> None:
        try:
            from cloudsneeker_api.tasks import evaluate_alert_rules_task

            evaluate_alert_rules_task.delay(
                tenant_id=str(tenant_id),
                scan_id=str(scan_id) if scan_id else None,
                custodian_run_id=str(custodian_run_id) if custodian_run_id else None,
            )
        except Exception:  # noqa: BLE001 - alerts must never fail a scan
            logger.exception("Could not queue alert evaluation tenant=%s", tenant_id)

    if using:
        transaction.on_commit(_send, using=using)
    else:
        transaction.on_commit(_send)
