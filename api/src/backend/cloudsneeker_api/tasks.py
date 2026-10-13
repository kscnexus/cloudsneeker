"""Celery tasks for Cloudsneeker feature backends."""

from celery import shared_task
from config.celery import RLSTask


@shared_task(base=RLSTask, name="cloudsneeker-process-finding-ingestion", queue="scans")
def process_finding_ingestion_task(tenant_id: str, ingestion_id: str):
    """Process an uploaded OCSF report into findings."""
    from cloudsneeker_api.services.ocsf_import import process_ingestion

    return process_ingestion(tenant_id=tenant_id, ingestion_id=ingestion_id)


@shared_task(base=RLSTask, name="cloudsneeker-evaluate-alert-rules", queue="scans")
def evaluate_alert_rules_task(tenant_id: str, scan_id: str | None = None):
    """Evaluate enabled after-scan alert rules and email confirmed recipients."""
    from api.db_utils import rls_transaction
    from api.models import Finding
    from cloudsneeker_api.models import AlertRecipient, AlertRule
    from cloudsneeker_api.services.alert_conditions import evaluate_condition
    from django.core.mail import send_mail

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
            emails = list(
                rule.recipients.filter(
                    status=AlertRecipient.Status.CONFIRMED
                ).values_list("email", flat=True)
            )
            if not emails:
                continue
            send_mail(
                subject=f"[Cloudsneeker] {rule.name}",
                message=(
                    f"Alert rule '{rule.name}' matched {count} finding(s).\n\n"
                    f"{rule.description or ''}"
                ),
                from_email=None,
                recipient_list=emails,
                fail_silently=True,
            )
            notified += 1
        return {"rules_notified": notified}
