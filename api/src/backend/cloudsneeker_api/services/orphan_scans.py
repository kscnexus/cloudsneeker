"""Fail scans whose Celery worker is gone.

A deploy, OOM kill, or task eviction stops the worker mid-scan. The scan row
stays ``executing`` and every later scan for that provider queues behind it.
The upstream orphan watchdog skips scan tasks on purpose (re-running the same
task is not safe), so this sweep marks the scan failed, then either dispatches
the provider's next queued scan or, when nothing is queued, launches one fresh
scan in its place. A relaunched scan is never relaunched again.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from api.db_utils import rls_transaction
from api.models import Scan, StateChoices
from celery import states
from tasks.jobs.orphan_recovery import advisory_lock, is_worker_alive

logger = logging.getLogger(__name__)

# Different key from the upstream orphan sweep so the two never block each other.
ORPHAN_SCAN_LOCK_KEY = 0x63736F73  # "csos"
GRACE_MINUTES = 5
IN_FLIGHT_TASK_STATES = (states.STARTED, states.RECEIVED, "PROGRESS")
# A busy worker can miss one short ping; failing a live scan would start a
# duplicate, so a worker only counts as gone after two longer missed pings.
PING_TIMEOUT_SECONDS = 5.0
PING_ATTEMPTS = 2
ORPHAN_ERROR = "Scan worker stopped before the scan finished (deploy or restart)."
RELAUNCH_MARKER = "cloudsneeker_relaunch_of"
RELAUNCH_NAME = "Relaunched after restart"
TRIVY_HUB_SOURCE = "trivy_hub"


def _worker_gone(worker: str) -> bool:
    return not any(
        is_worker_alive(worker, timeout=PING_TIMEOUT_SECONDS)
        for _ in range(PING_ATTEMPTS)
    )


def _orphaned_scans(tenant_id: str, cutoff: datetime) -> list[Scan]:
    """Return in-flight scans started before ``cutoff`` whose worker is gone."""
    candidates = (
        Scan.objects.filter(
            tenant_id=tenant_id,
            state__in=(
                StateChoices.EXECUTING,
                StateChoices.AVAILABLE,
                StateChoices.SCHEDULED,
            ),
            task__task_runner_task__status__in=IN_FLIGHT_TASK_STATES,
            task__task_runner_task__date_created__lt=cutoff,
        )
        .select_related("task__task_runner_task")
        .order_by("inserted_at")
    )
    orphans = []
    for scan in candidates:
        worker = scan.task.task_runner_task.worker
        if worker and _worker_gone(worker):
            orphans.append(scan)
    return orphans


def _fail_scan(scan: Scan, now: datetime) -> None:
    scan.state = StateChoices.FAILED
    scan.completed_at = now
    scan.save(update_fields=["state", "completed_at"])

    task_result = scan.task.task_runner_task
    task_result.status = states.FAILURE
    task_result.date_done = now
    task_result.result = ORPHAN_ERROR
    task_result.save(update_fields=["status", "date_done", "result"])


def _can_relaunch(scan: Scan) -> bool:
    args = scan.scanner_args or {}
    # Trivy Hub runs own their scans; a run is re-run from the hub instead.
    return not args.get(RELAUNCH_MARKER) and args.get("source") != TRIVY_HUB_SOURCE


def _relaunch_scan(tenant_id: str, orphan: Scan) -> Scan:
    """Launch a fresh scan for the orphan's provider, as Launch Scan would."""
    from tasks.jobs.attack_paths import db_utils as attack_paths_db_utils
    from tasks.tasks import create_scan_task_record, enqueue_scan_execution_on_commit

    task_id = str(uuid4())
    with rls_transaction(tenant_id):
        scan = Scan.objects.create(
            tenant_id=tenant_id,
            provider_id=orphan.provider_id,
            name=RELAUNCH_NAME,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.AVAILABLE,
            scanner_args={**(orphan.scanner_args or {}), RELAUNCH_MARKER: str(orphan.id)},
            task_id=task_id,
        )
        attack_paths_db_utils.create_attack_paths_scan(
            tenant_id=tenant_id,
            scan_id=str(scan.id),
            provider_id=str(scan.provider_id),
        )
        create_scan_task_record(
            tenant_id=tenant_id,
            task_id=task_id,
            task_kwargs={
                "tenant_id": str(tenant_id),
                "scan_id": str(scan.id),
                "provider_id": str(scan.provider_id),
            },
        )
        enqueue_scan_execution_on_commit(tenant_id=tenant_id, scan=scan, task_id=task_id)
    return scan


def fail_orphaned_scans(
    tenant_id: str, grace_minutes: int = GRACE_MINUTES
) -> list[str]:
    """Mark a tenant's orphaned scans failed and keep each provider scanning.

    For each affected provider the next queued scan is dispatched; when none is
    queued, a single fresh scan replaces the orphan.

    Args:
        tenant_id: Tenant to sweep.
        grace_minutes: Ignore tasks started more recently than this.

    Returns:
        IDs of the scans that were marked failed.
    """
    from tasks.tasks import _dispatch_next_queued_provider_scan

    now = datetime.now(UTC)
    with rls_transaction(tenant_id):
        orphans = _orphaned_scans(tenant_id, now - timedelta(minutes=grace_minutes))
        for scan in orphans:
            _fail_scan(scan, now)
            logger.warning(
                "Marked orphaned scan %s failed (worker %s gone)",
                scan.id,
                scan.task.task_runner_task.worker,
            )

    latest_by_provider = {str(scan.provider_id): scan for scan in orphans}
    for provider_id, orphan in latest_by_provider.items():
        try:
            if _dispatch_next_queued_provider_scan(tenant_id, provider_id):
                continue
            if _can_relaunch(orphan):
                relaunched = _relaunch_scan(tenant_id, orphan)
                logger.warning(
                    "Relaunched orphaned scan %s as %s", orphan.id, relaunched.id
                )
        except Exception:
            logger.exception(
                "Failed to resume scanning for provider %s after orphan %s",
                provider_id,
                orphan.id,
            )

    return [str(scan.id) for scan in orphans]


def fail_orphaned_scans_all_tenants(grace_minutes: int = GRACE_MINUTES) -> dict:
    """Run :func:`fail_orphaned_scans` for every tenant under one advisory lock."""
    from api.models import Tenant

    with advisory_lock(key=ORPHAN_SCAN_LOCK_KEY) as acquired:
        if not acquired:
            return {"acquired": False, "failed_scans": []}
        failed: list[str] = []
        for tenant_id in Tenant.objects.values_list("id", flat=True):
            failed.extend(
                fail_orphaned_scans(str(tenant_id), grace_minutes=grace_minutes)
            )
        return {"acquired": True, "failed_scans": failed}
