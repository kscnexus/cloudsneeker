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
def evaluate_alert_rules_task(
    tenant_id: str,
    scan_id: str | None = None,
    custodian_run_id: str | None = None,
    trigger: str = "after_scan",
):
    """Evaluate enabled alert rules and notify email and Slack destinations.

    ``after_scan`` runs once per finished scan: a cloud or application scan
    (``scan_id``) or a governance policy run (``custodian_run_id``). ``daily``
    looks at the current state: the latest scan per provider and target and
    the latest run per policy.
    """
    from cloudsneeker_api.services.alert_dispatch import evaluate_and_notify

    return evaluate_and_notify(
        tenant_id=tenant_id,
        scan_id=scan_id,
        custodian_run_id=custodian_run_id,
        trigger=trigger,
    )


@shared_task(name="cloudsneeker-evaluate-daily-alert-rules", queue="celery")
def evaluate_daily_alert_rules_task():
    """Celery Beat entrypoint: queue daily alert evaluation per tenant."""
    from cloudsneeker_api.services.alert_dispatch import tenants_with_daily_rules

    tenant_ids = tenants_with_daily_rules()
    for tenant_id in tenant_ids:
        evaluate_alert_rules_task.delay(tenant_id=tenant_id, trigger="daily")
    return {"tenants": len(tenant_ids)}


@shared_task(base=RLSTask, name="cloudsneeker-custodian-dry-run", queue="scans")
@set_tenant(keep_tenant=True)
def custodian_dry_run_task(tenant_id: str, run_id: str):
    """Run a Cloud Custodian policy in dry-run mode only."""
    from cloudsneeker_api.services.custodian import process_custodian_dry_run

    return process_custodian_dry_run(tenant_id=tenant_id, run_id=run_id)


@shared_task(
    base=RLSTask,
    name="cloudsneeker-custodian-scheduled-dry-run",
    queue="scans",
)
@set_tenant(keep_tenant=True)
def custodian_scheduled_dry_run_task(tenant_id: str, policy_id: str):
    """Celery Beat entrypoint: enqueue a scheduled Custodian dry-run."""
    from cloudsneeker_api.services.custodian_schedule import enqueue_scheduled_dry_run

    run = enqueue_scheduled_dry_run(tenant_id=tenant_id, policy_id=policy_id)
    if run is None:
        return {"status": "skipped", "policy_id": str(policy_id)}
    return {"status": "enqueued", "run_id": str(run.id), "policy_id": str(policy_id)}


@shared_task(name="cloudsneeker-custodian-trim-outputs", queue="scans")
def custodian_trim_outputs_task(older_than_days: int = 30):
    """Clear raw resource lists from old completed Custodian runs (all tenants)."""
    from api.db_router import MainRouter
    from api.models import Tenant
    from cloudsneeker_api.services.custodian import trim_old_custodian_run_output

    trimmed_total = 0
    tenant_ids = Tenant.objects.using(MainRouter.admin_db).values_list("id", flat=True)
    for tenant_id in tenant_ids:
        trimmed_total += trim_old_custodian_run_output(
            tenant_id=str(tenant_id),
            older_than_days=older_than_days,
        )
    return {"trimmed_runs": trimmed_total}


@shared_task(name="cloudsneeker-fail-orphaned-scans", queue="celery")
def fail_orphaned_scans_task():
    """Celery Beat entrypoint: fail scans whose worker died and release the queue."""
    from cloudsneeker_api.services.orphan_scans import fail_orphaned_scans_all_tenants

    return fail_orphaned_scans_all_tenants()


@shared_task(base=RLSTask, name="cloudsneeker-trivy-scan", queue="scans")
@set_tenant(keep_tenant=True)
def trivy_scan_task(tenant_id: str, run_id: str):
    """Run a Trivy Hub scan and import findings into the shared Scan table."""
    from cloudsneeker_api.services.trivy import process_trivy_run

    return process_trivy_run(tenant_id=tenant_id, run_id=run_id)


@shared_task(
    base=RLSTask,
    name="cloudsneeker-trivy-scheduled-scan",
    queue="scans",
)
@set_tenant(keep_tenant=True)
def trivy_scheduled_scan_task(tenant_id: str, target_id: str):
    """Celery Beat entrypoint: enqueue a scheduled Trivy Hub scan."""
    from cloudsneeker_api.services.trivy_schedule import enqueue_scheduled_trivy_run

    run = enqueue_scheduled_trivy_run(tenant_id=tenant_id, target_id=target_id)
    if run is None:
        return {"status": "skipped", "target_id": str(target_id)}
    return {
        "status": "enqueued",
        "run_id": str(run.id),
        "target_id": str(target_id),
    }


@shared_task(base=RLSTask, name="cloudsneeker-appsec-rescore", queue="scans")
@set_tenant(keep_tenant=True)
def appsec_rescore_task(
    tenant_id: str,
    application_id: str | None = None,
    target_ids: list[str] | None = None,
):
    """Recompute finding priority and deadlines after a settings or
    application change."""
    from cloudsneeker_api.appsec.maintenance import rescore

    return {
        "rescored": rescore(
            tenant_id=tenant_id, application_id=application_id, target_ids=target_ids
        )
    }


@shared_task(base=RLSTask, name="cloudsneeker-appsec-record-branches", queue="scans")
@set_tenant(keep_tenant=True)
def appsec_record_branches_task(tenant_id: str):
    """Record the branch of every repository and static analysis target saved
    without one, and put it in the target's name."""
    from cloudsneeker_api.services.repo_branches import backfill_target_branches

    return backfill_target_branches(tenant_id)


@shared_task(name="cloudsneeker-appsec-retention", queue="celery")
def appsec_retention_task():
    """Celery Beat entrypoint: apply raw report and fixed finding retention."""
    from cloudsneeker_api.appsec.maintenance import apply_retention_all_tenants

    return apply_retention_all_tenants()


@shared_task(base=RLSTask, name="cloudsneeker-generate-report", queue="scans")
@set_tenant(keep_tenant=True)
def generate_report_task(tenant_id: str, run_id: str):
    """Assemble and render a pending report run."""
    from cloudsneeker_api.reports.runs import process_report_run

    return process_report_run(tenant_id=tenant_id, run_id=run_id)


@shared_task(base=RLSTask, name="cloudsneeker-scheduled-report", queue="scans")
@set_tenant(keep_tenant=True)
def scheduled_report_task(tenant_id: str, schedule_id: str):
    """Celery Beat entrypoint: generate a scheduled report and email it."""
    from cloudsneeker_api.reports.schedule import run_scheduled_report

    return run_scheduled_report(tenant_id=tenant_id, schedule_id=schedule_id)


# --- Audit log (EB-007) -------------------------------------------------------


@shared_task(name="cloudsneeker-purge-audit-events", queue="celery")
def purge_audit_events_task(older_than_days: int | None = None):
    """Celery Beat entrypoint: delete audit events past the retention window.

    The window is ``AUDIT_LOG_RETENTION_DAYS`` (default 365). Each tenant is
    purged in its own RLS transaction.
    """
    from api.db_router import MainRouter
    from api.models import Tenant
    from cloudsneeker_api.audit import purge_all_tenants, retention_days

    days = older_than_days or retention_days()
    tenant_ids = Tenant.objects.using(MainRouter.admin_db).values_list("id", flat=True)
    return {"deleted": purge_all_tenants(tenant_ids, days), "retention_days": days}


# --- Application Security scan history ------------------------------------------


@shared_task(name="cloudsneeker-archive-trivy-runs", queue="celery")
def archive_trivy_runs_task(older_than_days: int | None = None):
    """Celery Beat entrypoint: archive Application Security runs past the window.

    The window is ``APP_SECURITY_SCAN_ARCHIVE_DAYS`` (default 365). Each tenant
    is archived in its own RLS transaction.
    """
    from api.db_router import MainRouter
    from api.models import Tenant
    from cloudsneeker_api.services.trivy_history import (
        archive_all_tenants,
        archive_days,
    )

    days = older_than_days or archive_days()
    tenant_ids = Tenant.objects.using(MainRouter.admin_db).values_list("id", flat=True)
    return {"archived": archive_all_tenants(tenant_ids, days), "archive_days": days}


# --- Operator console (Phase 1) -----------------------------------------------


@shared_task(name="cloudsneeker-operator-daily", queue="celery")
def operator_daily_task():
    """Celery Beat entrypoint: expire ended subscriptions, then snapshot usage.

    Cross-tenant: the operator tables are not row-level security protected
    and the usage counts are read through the admin connection, so no tenant
    is set.
    """
    from cloudsneeker_api.services import bootstrap_operators
    from cloudsneeker_api.services.entitlements import (
        expire_subscriptions,
        snapshot_usage,
    )

    expired = expire_subscriptions()
    snapshots = snapshot_usage()
    bootstrapped = bootstrap_operators.reconcile()
    return {
        "expired": expired,
        "snapshots": snapshots,
        "bootstrap_operators": bootstrapped,
    }


# --- Shared vulnerability database (EB-047) -----------------------------------


@shared_task(name="cloudsneeker-refresh-vuln-db", queue="celery")
def refresh_vuln_db_task():
    """Celery Beat entrypoint: download a fresh Trivy database snapshot.

    Does nothing when the shared cache is not configured.
    """
    from cloudsneeker_api.services import vuln_db

    if vuln_db.cache_root() is None:
        return {"refreshed": False, "reason": "not configured"}
    snapshot = vuln_db.refresh()
    return {
        "refreshed": True,
        "snapshot": snapshot.path.name,
        "java_db": snapshot.java_db,
    }


# --- Exploit intelligence (EB-022) --------------------------------------------


@shared_task(name="cloudsneeker-refresh-vuln-intel", queue="celery")
def refresh_vuln_intel_task():
    """Celery Beat entrypoint: refresh the EPSS and CISA KEV feeds."""
    from cloudsneeker_api.services import vuln_intel

    return vuln_intel.refresh()


# --- Risk acceptance expiry (EB-019) ------------------------------------------


@shared_task(name="cloudsneeker-expire-risk-acceptances", queue="celery")
def expire_risk_acceptances_task():
    """Celery Beat entrypoint: reopen expired risk acceptances, email owners."""
    from cloudsneeker_api.services import risk_acceptance

    expired = risk_acceptance.expire_risk_acceptances()
    return {
        "reopened": len(expired),
        "emails_sent": risk_acceptance.notify_owners(expired) if expired else 0,
    }
