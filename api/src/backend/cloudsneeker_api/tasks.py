"""Celery tasks for Cloudsneeker feature backends."""

import logging

from api.decorators import set_tenant
from celery import shared_task
from config.celery import RLSTask

logger = logging.getLogger(__name__)


@shared_task(base=RLSTask, name="cloudsneeker-process-finding-ingestion", queue="scans")
@set_tenant(keep_tenant=True)
def process_finding_ingestion_task(tenant_id: str, ingestion_id: str):
    """Process an uploaded OCSF report into findings."""
    from cloudsneeker_api.services.ocsf_import import process_ingestion

    return process_ingestion(tenant_id=tenant_id, ingestion_id=ingestion_id)


@shared_task(base=RLSTask, name="cloudsneeker-evaluate-alert-rules", queue="scans")
@set_tenant(keep_tenant=True)
def evaluate_alert_rules_task(tenant_id: str, scan_id: str | None = None):
    """Evaluate enabled after-scan alert rules and notify email/Slack destinations."""
    from api.db_utils import rls_transaction
    from api.models import Finding
    from cloudsneeker_api.models import AlertRecipient, AlertRule
    from cloudsneeker_api.services.alert_conditions import evaluate_condition
    from cloudsneeker_api.services.email_delivery import send_with_tenant_smtp
    from cloudsneeker_api.services.slack import post_alert_to_channels

    with rls_transaction(tenant_id):
        rules = AlertRule.objects.filter(
            tenant_id=tenant_id,
            enabled=True,
            trigger__in=[
                AlertRule.Trigger.AFTER_SCAN,
                AlertRule.Trigger.BOTH,
            ],
        ).prefetch_related("recipients")
        findings = Finding.all_objects.filter(tenant_id=tenant_id)
        if scan_id:
            findings = findings.filter(scan_id=scan_id)

        notified = 0
        for rule in rules:
            matched, queryset = evaluate_condition(findings, rule.condition or {})
            if not matched:
                continue
            count = queryset.count()
            body = (
                f"Alert rule '{rule.name}' matched {count} finding(s).\n\n"
                f"{rule.description or ''}"
            ).strip()
            subject = f"[Cloudsneeker] {rule.name}"

            emails = list(
                rule.recipients.filter(
                    status=AlertRecipient.Status.CONFIRMED
                ).values_list("email", flat=True)
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
                        "Alert email delivery failed tenant=%s rule=%s",
                        tenant_id,
                        rule.id,
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
                        "Alert Slack delivery failed tenant=%s rule=%s",
                        tenant_id,
                        rule.id,
                    )

            if emails or channel_ids:
                notified += 1
        return {"rules_notified": notified}


@shared_task(base=RLSTask, name="cloudsneeker-custodian-dry-run", queue="scans")
@set_tenant(keep_tenant=True)
def custodian_dry_run_task(tenant_id: str, run_id: str):
    """Run a Cloud Custodian policy in dry-run mode only."""
    from cloudsneeker_api.services.custodian import process_custodian_dry_run

    return process_custodian_dry_run(tenant_id=tenant_id, run_id=run_id)
