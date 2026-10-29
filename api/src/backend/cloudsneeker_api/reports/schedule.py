"""Sync report schedules to django-celery-beat and run them."""

from __future__ import annotations

import json
import logging
from typing import Any

from api.db_utils import rls_transaction
from cloudsneeker_api.models import ReportRun, ReportSchedule
from cloudsneeker_api.services.custodian_schedule import (
    compute_next_run_at,
    parse_cron_fields,
    validate_timezone,
)
from django.utils import timezone
from django_celery_beat.models import CrontabSchedule, PeriodicTask

logger = logging.getLogger(__name__)

SCHEDULED_TASK_NAME = "cloudsneeker-scheduled-report"
PERIODIC_TASK_PREFIX = "report-scheduled-"


class ReportScheduleError(ValueError):
    """Raised when a schedule's cron or timezone is invalid."""


def periodic_task_name(schedule_id: str) -> str:
    """Return the unique Celery Beat task name for a report schedule."""
    return f"{PERIODIC_TASK_PREFIX}{schedule_id}"


def sync_report_schedule(schedule: ReportSchedule) -> ReportSchedule:
    """Create, update, or disable the PeriodicTask of a report schedule.

    Args:
        schedule: Saved schedule.

    Returns:
        The schedule with ``scheduler_task`` and ``next_run_at`` refreshed.

    Raises:
        ReportScheduleError: Invalid cron expression or timezone.
    """
    task_name = periodic_task_name(str(schedule.id))
    if not schedule.enabled:
        periodic = PeriodicTask.objects.filter(name=task_name).first()
        if periodic is not None:
            periodic.enabled = False
            periodic.save(update_fields=["enabled"])
        schedule.scheduler_task = None
        schedule.next_run_at = None
        schedule.save(update_fields=["scheduler_task", "next_run_at", "updated_at"])
        return schedule

    try:
        tz_name = validate_timezone(schedule.schedule_timezone)
        minute, hour, day_of_month, month, day_of_week = parse_cron_fields(
            schedule.schedule_cron
        )
    except Exception as exc:  # noqa: BLE001 - surface any parse error as input error
        raise ReportScheduleError(str(exc)) from exc

    crontab, _ = CrontabSchedule.objects.get_or_create(
        minute=minute,
        hour=hour,
        day_of_month=day_of_month,
        month_of_year=month,
        day_of_week=day_of_week,
        timezone=tz_name,
    )
    kwargs = json.dumps(
        {"tenant_id": str(schedule.tenant_id), "schedule_id": str(schedule.id)}
    )
    periodic, _ = PeriodicTask.objects.update_or_create(
        name=task_name,
        defaults={
            "crontab": crontab,
            "interval": None,
            "solar": None,
            "clocked": None,
            "task": SCHEDULED_TASK_NAME,
            "kwargs": kwargs,
            "one_off": False,
            "enabled": True,
        },
    )
    schedule.schedule_timezone = tz_name
    schedule.scheduler_task = periodic
    schedule.next_run_at = compute_next_run_at(schedule.schedule_cron, tz_name)
    schedule.save(
        update_fields=["schedule_timezone", "scheduler_task", "next_run_at", "updated_at"]
    )
    return schedule


def delete_report_schedule_task(schedule_id: str) -> None:
    """Remove the PeriodicTask of a deleted schedule."""
    PeriodicTask.objects.filter(name=periodic_task_name(schedule_id)).delete()


def run_scheduled_report(*, tenant_id: str, schedule_id: str) -> dict[str, Any]:
    """Generate a schedule's report inline and email it to its recipients.

    Args:
        tenant_id: Tenant UUID string.
        schedule_id: Schedule UUID string.

    Returns:
        ``{"status", ...}``: ``skipped`` (missing or disabled), ``failed``
        (generation failed), or ``completed`` with delivery details.
    """
    from cloudsneeker_api.reports.delivery import deliver_report_email
    from cloudsneeker_api.reports.runs import enqueue_report_run, process_report_run

    with rls_transaction(tenant_id):
        schedule = ReportSchedule.objects.filter(tenant_id=tenant_id, id=schedule_id).first()
        if schedule is None or not schedule.enabled:
            return {"status": "skipped", "schedule_id": str(schedule_id)}
        report_type = schedule.report_type
        params = dict(schedule.params or {})
        formats = list(schedule.formats or [])
        recipients = [email for email in schedule.recipients or [] if email]
        created_by_id = str(schedule.created_by_id) if schedule.created_by_id else None

    run = enqueue_report_run(
        tenant_id=tenant_id,
        report_type=report_type,
        params=params,
        formats=formats,
        created_by_id=created_by_id,
        trigger=ReportRun.Trigger.SCHEDULED,
        schedule_id=str(schedule_id),
        dispatch=False,
    )
    result = process_report_run(tenant_id=tenant_id, run_id=str(run.id))

    with rls_transaction(tenant_id):
        schedule = ReportSchedule.objects.get(tenant_id=tenant_id, id=schedule_id)
        schedule.last_run_at = timezone.now()
        schedule.last_run_id = run.id
        if schedule.schedule_cron:
            try:
                schedule.next_run_at = compute_next_run_at(
                    schedule.schedule_cron, schedule.schedule_timezone
                )
            except Exception:  # noqa: BLE001 - keep the old value on a bad cron
                logger.warning("Bad cron on report schedule %s", schedule_id)
        schedule.save(update_fields=["last_run_at", "last_run", "next_run_at", "updated_at"])
        run.refresh_from_db()

    if result["status"] != ReportRun.Status.COMPLETED:
        return {"status": "failed", "run_id": str(run.id), "schedule_id": str(schedule_id)}

    delivery = deliver_report_email(tenant_id=tenant_id, run=run, recipients=recipients)
    return {
        "status": "completed",
        "run_id": str(run.id),
        "schedule_id": str(schedule_id),
        **delivery,
    }
