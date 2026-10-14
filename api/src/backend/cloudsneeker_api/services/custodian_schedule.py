"""Sync Custodian policy schedules to django-celery-beat.

Schedules are per-policy, dry-run only, and use a 5-field cron expression
plus an IANA timezone. Task names are namespaced so they never collide with
scan ``scan-perform-scheduled-*`` entries.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from api.db_utils import rls_transaction
from cloudsneeker_api.models import CustodianPolicy, CustodianRun
from cloudsneeker_api.services.custodian import CustodianDryRunError
from django.utils import timezone
from django_celery_beat.models import CrontabSchedule, PeriodicTask

SCHEDULED_TASK_NAME = "cloudsneeker-custodian-scheduled-dry-run"
PERIODIC_TASK_PREFIX = "custodian-dry-run-scheduled-"

_CRON_FIELD_RE = re.compile(
    r"^(\*|\*/\d+|\d+(-\d+)?(,\d+(-\d+)?)*)(/(\d+))?$"
)


class CustodianScheduleError(CustodianDryRunError):
    """Raised when schedule cron or timezone input is invalid."""


def periodic_task_name(policy_id: str) -> str:
    """Return the unique Celery Beat task name for a policy."""
    return f"{PERIODIC_TASK_PREFIX}{policy_id}"


def parse_cron_fields(cron: str) -> tuple[str, str, str, str, str]:
    """Split and validate a 5-field cron expression.

    Fields are minute, hour, day_of_month, month_of_year, day_of_week
    (django-celery-beat / standard crontab order).
    """
    if not cron or not cron.strip():
        raise CustodianScheduleError("schedule_cron is required when the schedule is enabled.")
    parts = cron.strip().split()
    if len(parts) != 5:
        raise CustodianScheduleError(
            "schedule_cron must be a 5-field expression "
            "(minute hour day_of_month month day_of_week)."
        )
    labels = ("minute", "hour", "day_of_month", "month", "day_of_week")
    for label, part in zip(labels, parts, strict=True):
        if not _CRON_FIELD_RE.match(part):
            raise CustodianScheduleError(f"Invalid cron {label} field: {part}")
    return parts[0], parts[1], parts[2], parts[3], parts[4]


def validate_timezone(tz_name: str) -> str:
    """Return a validated IANA timezone name."""
    name = (tz_name or "UTC").strip() or "UTC"
    try:
        ZoneInfo(name)
    except ZoneInfoNotFoundError as exc:
        raise CustodianScheduleError(f"Unknown timezone: {name}") from exc
    return name


def compute_next_run_at(cron: str, tz_name: str, *, now: datetime | None = None) -> datetime:
    """Compute the next fire time in UTC for a cron + timezone."""
    minute, hour, day_of_month, month, day_of_week = parse_cron_fields(cron)
    tz = ZoneInfo(validate_timezone(tz_name))
    base = now or timezone.now()
    if base.tzinfo is None:
        base = timezone.make_aware(base, timezone=timezone.utc)
    local_base = base.astimezone(tz)

    try:
        from croniter import croniter
    except ImportError:
        # Fallback: approximate from crontab without croniter.
        return base

    expr = f"{minute} {hour} {day_of_month} {month} {day_of_week}"
    iterator = croniter(expr, local_base)
    nxt = iterator.get_next(datetime)
    if nxt.tzinfo is None:
        nxt = nxt.replace(tzinfo=tz)
    return nxt.astimezone(timezone.utc)


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


def sync_policy_schedule(policy: CustodianPolicy) -> CustodianPolicy:
    """Create, update, or disable the PeriodicTask for a policy.

    Args:
        policy: Policy row already loaded in an RLS context.

    Returns:
        The updated policy instance.
    """
    task_name = periodic_task_name(str(policy.id))
    tenant_id = str(policy.tenant_id)
    policy_id = str(policy.id)

    if not policy.schedule_enabled:
        return _disable_schedule(policy, task_name)

    tz_name = validate_timezone(policy.schedule_timezone)
    minute, hour, day_of_month, month, day_of_week = parse_cron_fields(
        policy.schedule_cron
    )
    crontab = _get_or_create_crontab(
        minute=minute,
        hour=hour,
        day_of_month=day_of_month,
        month_of_year=month,
        day_of_week=day_of_week,
        tz_name=tz_name,
    )
    next_run = compute_next_run_at(policy.schedule_cron, tz_name)

    kwargs = json.dumps({"tenant_id": tenant_id, "policy_id": policy_id})
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

    policy.schedule_timezone = tz_name
    policy.scheduler_task = periodic
    policy.next_run_at = next_run
    policy.save(
        update_fields=[
            "schedule_timezone",
            "scheduler_task",
            "next_run_at",
            "updated_at",
        ]
    )
    return policy


def _disable_schedule(policy: CustodianPolicy, task_name: str) -> CustodianPolicy:
    periodic = PeriodicTask.objects.filter(name=task_name).first()
    if periodic is not None:
        periodic.enabled = False
        periodic.save(update_fields=["enabled"])
    policy.scheduler_task = None
    policy.next_run_at = None
    policy.save(update_fields=["scheduler_task", "next_run_at", "updated_at"])
    return policy


def delete_policy_schedule(policy_id: str) -> None:
    """Remove the PeriodicTask for a deleted policy."""
    PeriodicTask.objects.filter(name=periodic_task_name(policy_id)).delete()


def apply_schedule_to_policies(
    *,
    tenant_id: str,
    schedule_enabled: bool,
    schedule_cron: str = "",
    schedule_timezone: str = "UTC",
    policy_ids: list[str] | None = None,
    provider_id: str | None = None,
) -> list[CustodianPolicy]:
    """Apply the same schedule to many policies (by id or provider)."""
    if not policy_ids and not provider_id:
        raise CustodianScheduleError(
            "Provide policy_ids or provider_id for bulk schedule updates."
        )
    if schedule_enabled:
        parse_cron_fields(schedule_cron)
        schedule_timezone = validate_timezone(schedule_timezone)

    with rls_transaction(tenant_id):
        queryset = CustodianPolicy.objects.filter(tenant_id=tenant_id)
        if policy_ids:
            queryset = queryset.filter(id__in=policy_ids)
        if provider_id:
            queryset = queryset.filter(provider_id=provider_id)
        policies = list(queryset.select_related("provider"))
        if not policies:
            raise CustodianScheduleError("No Custodian policies matched the bulk filter.")

        updated: list[CustodianPolicy] = []
        for policy in policies:
            policy.schedule_enabled = schedule_enabled
            policy.schedule_cron = schedule_cron if schedule_enabled else ""
            policy.schedule_timezone = (
                schedule_timezone if schedule_enabled else "UTC"
            )
            policy.save(
                update_fields=[
                    "schedule_enabled",
                    "schedule_cron",
                    "schedule_timezone",
                    "updated_at",
                ]
            )
            updated.append(sync_policy_schedule(policy))
        return updated


def has_active_run(*, tenant_id: str, policy_id: str) -> bool:
    """Return True when a pending or running dry-run already exists."""
    with rls_transaction(tenant_id):
        return CustodianRun.objects.filter(
            tenant_id=tenant_id,
            policy_id=policy_id,
            status__in=[
                CustodianRun.Status.PENDING,
                CustodianRun.Status.RUNNING,
            ],
        ).exists()


def enqueue_scheduled_dry_run(*, tenant_id: str, policy_id: str) -> CustodianRun | None:
    """Enqueue a scheduled dry-run, skipping when one is already active.

    Returns:
        The new run, or ``None`` when skipped due to overlap or a disabled schedule.
    """
    from cloudsneeker_api.services.custodian import enqueue_custodian_dry_run

    with rls_transaction(tenant_id):
        policy = CustodianPolicy.objects.filter(
            tenant_id=tenant_id, id=policy_id
        ).first()
        if policy is None or not policy.schedule_enabled:
            return None

    if has_active_run(tenant_id=tenant_id, policy_id=policy_id):
        return None

    run = enqueue_custodian_dry_run(
        tenant_id=tenant_id,
        policy_id=policy_id,
        trigger=CustodianRun.Trigger.SCHEDULED,
    )

    with rls_transaction(tenant_id):
        policy = CustodianPolicy.objects.filter(
            tenant_id=tenant_id, id=policy_id
        ).first()
        if policy and policy.schedule_enabled and policy.schedule_cron:
            policy.next_run_at = compute_next_run_at(
                policy.schedule_cron, policy.schedule_timezone
            )
            policy.save(update_fields=["next_run_at", "updated_at"])
    return run
