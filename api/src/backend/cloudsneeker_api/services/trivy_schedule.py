"""Sync Trivy Hub target schedules to django-celery-beat."""

from __future__ import annotations

import json

from api.db_utils import rls_transaction
from cloudsneeker_api.models import TrivyRun, TrivyTarget
from cloudsneeker_api.services.custodian_schedule import (
    compute_next_run_at,
    parse_cron_fields,
    validate_timezone,
)
from cloudsneeker_api.services.trivy import TrivyHubError
from django_celery_beat.models import CrontabSchedule, PeriodicTask

SCHEDULED_TASK_NAME = "cloudsneeker-trivy-scheduled-scan"
PERIODIC_TASK_PREFIX = "trivy-scan-scheduled-"


class TrivyScheduleError(TrivyHubError):
    """Raised when Trivy schedule cron or timezone input is invalid."""


def periodic_task_name(target_id: str) -> str:
    """Return the unique Celery Beat task name for a Trivy target."""
    return f"{PERIODIC_TASK_PREFIX}{target_id}"


def _get_or_create_crontab(
    *,
    minute: str,
    hour: str,
    day_of_month: str,
    month_of_year: str,
    day_of_week: str,
    tz_name: str,
) -> CrontabSchedule:
    schedule, _ = CrontabSchedule.objects.get_or_create(
        minute=minute,
        hour=hour,
        day_of_month=day_of_month,
        month_of_year=month_of_year,
        day_of_week=day_of_week,
        timezone=tz_name,
    )
    return schedule


def sync_target_schedule(target: TrivyTarget) -> TrivyTarget:
    """Create, update, or disable the PeriodicTask for a Trivy target."""
    task_name = periodic_task_name(str(target.id))
    tenant_id = str(target.tenant_id)
    target_id = str(target.id)

    if not target.schedule_enabled:
        return _disable_schedule(target, task_name)

    try:
        tz_name = validate_timezone(target.schedule_timezone)
        minute, hour, day_of_month, month, day_of_week = parse_cron_fields(
            target.schedule_cron
        )
    except Exception as exc:  # noqa: BLE001
        raise TrivyScheduleError(str(exc)) from exc

    crontab = _get_or_create_crontab(
        minute=minute,
        hour=hour,
        day_of_month=day_of_month,
        month_of_year=month,
        day_of_week=day_of_week,
        tz_name=tz_name,
    )
    next_run = compute_next_run_at(target.schedule_cron, tz_name)
    kwargs = json.dumps({"tenant_id": tenant_id, "target_id": target_id})
    periodic = PeriodicTask.objects.filter(name=task_name).first()
    if periodic is None:
        periodic = PeriodicTask.objects.create(
            crontab=crontab,
            name=task_name,
            task=SCHEDULED_TASK_NAME,
            kwargs=kwargs,
            one_off=False,
            enabled=True,
        )
    else:
        periodic.crontab = crontab
        periodic.interval = None
        periodic.solar = None
        periodic.clocked = None
        periodic.task = SCHEDULED_TASK_NAME
        periodic.kwargs = kwargs
        periodic.enabled = True
        periodic.one_off = False
        periodic.save(
            update_fields=[
                "crontab",
                "interval",
                "solar",
                "clocked",
                "task",
                "kwargs",
                "enabled",
                "one_off",
            ]
        )

    target.schedule_timezone = tz_name
    target.scheduler_task = periodic
    target.next_run_at = next_run
    target.save(
        update_fields=[
            "schedule_timezone",
            "scheduler_task",
            "next_run_at",
            "updated_at",
        ]
    )
    return target


def _disable_schedule(target: TrivyTarget, task_name: str) -> TrivyTarget:
    periodic = PeriodicTask.objects.filter(name=task_name).first()
    if periodic is not None:
        periodic.enabled = False
        periodic.save(update_fields=["enabled"])
    target.scheduler_task = None
    target.next_run_at = None
    target.save(update_fields=["scheduler_task", "next_run_at", "updated_at"])
    return target


def delete_target_schedule(target_id: str) -> None:
    """Remove the PeriodicTask for a deleted Trivy target."""
    PeriodicTask.objects.filter(name=periodic_task_name(target_id)).delete()


def enqueue_scheduled_trivy_run(
    *, tenant_id: str, target_id: str
) -> TrivyRun | None:
    """Enqueue a scheduled Trivy run, skipping when one is already active."""
    from cloudsneeker_api.services.trivy import enqueue_trivy_run

    with rls_transaction(tenant_id):
        target = TrivyTarget.objects.filter(
            tenant_id=tenant_id, id=target_id
        ).first()
        if target is None or not target.schedule_enabled:
            return None
        active = TrivyRun.objects.filter(
            tenant_id=tenant_id,
            target_id=target_id,
            status__in=[TrivyRun.Status.PENDING, TrivyRun.Status.RUNNING],
        ).exists()
        if active:
            return None

    run = enqueue_trivy_run(
        tenant_id=tenant_id,
        target_id=target_id,
        trigger=TrivyRun.Trigger.SCHEDULED,
    )

    with rls_transaction(tenant_id):
        target = TrivyTarget.objects.filter(
            tenant_id=tenant_id, id=target_id
        ).first()
        if target and target.schedule_enabled and target.schedule_cron:
            target.next_run_at = compute_next_run_at(
                target.schedule_cron, target.schedule_timezone
            )
            target.save(update_fields=["next_run_at", "updated_at"])
    return run
