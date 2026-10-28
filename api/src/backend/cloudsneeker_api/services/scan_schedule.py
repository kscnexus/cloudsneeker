"""Provider scan schedules synced to django-celery-beat.

Implements the UI ``/schedules`` contract (daily / weekly / monthly / interval)
on top of the existing ``scan-perform-scheduled`` Celery task name used by OSS.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from api.db_utils import rls_transaction
from api.models import Provider, Scan, StateChoices
from django_celery_beat.models import CrontabSchedule, IntervalSchedule, PeriodicTask
from tasks.jobs.attack_paths import db_utils as attack_paths_db_utils

SCAN_FREQUENCIES = frozenset({"DAILY", "WEEKLY", "MONTHLY", "INTERVAL"})
TASK_NAME_PREFIX = "scan-perform-scheduled-"
CELERY_TASK = "scan-perform-scheduled"
MIN_INTERVAL_HOURS = 24


class ScanScheduleError(ValueError):
    """Invalid schedule attributes."""


def periodic_task_name(provider_id: str) -> str:
    return f"{TASK_NAME_PREFIX}{provider_id}"


def next_run_after(periodic_task: PeriodicTask, after: datetime) -> datetime:
    """Return the first run of ``periodic_task`` strictly after ``after``.

    OSS scan tasks always use an interval; DAILY / WEEKLY / MONTHLY schedules
    created here use a crontab, which the upstream scheduled-scan task cannot
    step through on its own.

    Args:
        periodic_task: The provider's ``scan-perform-scheduled`` beat task.
        after: Timezone-aware reference time.

    Returns:
        The next run time in UTC.

    Raises:
        ScanScheduleError: The task has neither an interval nor a crontab.
    """
    if periodic_task.interval_id:
        interval = periodic_task.interval
        return after + timedelta(**{interval.period: interval.every})
    if periodic_task.crontab_id:
        schedule = periodic_task.crontab.schedule
        # remaining_estimate reads the crontab fields in the reference time's
        # zone, so convert first (beat's is_due does the same).
        remaining = schedule.remaining_estimate(after.astimezone(schedule.tz))
        return (schedule.now() + remaining).astimezone(UTC).replace(microsecond=0)
    raise ScanScheduleError("Scheduled scan task has no interval or crontab.")


def advance_past_now(periodic_task: PeriodicTask, next_dt: datetime) -> datetime:
    """Step ``next_dt`` forward until it is in the future."""
    now = datetime.now(UTC)
    while next_dt <= now:
        next_dt = next_run_after(periodic_task, next_dt)
    return next_dt


def scheduled_scan_window(
    periodic_task: PeriodicTask, upstream_next: Callable[[], datetime]
) -> tuple[datetime, datetime]:
    """Return ``(next_run, current_run)`` for a scheduled scan execution.

    Interval tasks keep the upstream calculation unchanged. Crontab tasks run
    now and schedule the next crontab fire time.

    Args:
        periodic_task: The provider's ``scan-perform-scheduled`` beat task.
        upstream_next: Upstream ``get_next_execution_datetime`` bound to the run.

    Returns:
        The next run time and the time this run is recorded for.
    """
    if periodic_task.interval_id:
        next_dt = upstream_next()
        interval = periodic_task.interval
        return next_dt, next_dt - timedelta(**{interval.period: interval.every})

    now = datetime.now(UTC)
    return next_run_after(periodic_task, now), now


def validate_timezone(name: str) -> str:
    text = (name or "").strip() or "UTC"
    try:
        ZoneInfo(text)
    except ZoneInfoNotFoundError as exc:
        raise ScanScheduleError(f"Unknown timezone: {text}") from exc
    return text


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


def _disable_periodic_task(task_name: str) -> None:
    PeriodicTask.objects.filter(name=task_name).update(enabled=False)


def _ensure_available_scan(
    *,
    tenant_id: str,
    provider_id: str,
    periodic_task: PeriodicTask,
    schedule_label: str,
) -> Scan:
    scheduled_at = next_run_after(periodic_task, datetime.now(UTC))
    with rls_transaction(tenant_id):
        existing = (
            Scan.objects.filter(
                tenant_id=tenant_id,
                provider_id=provider_id,
                trigger=Scan.TriggerChoices.SCHEDULED,
                state__in=(StateChoices.AVAILABLE, StateChoices.SCHEDULED),
                task__isnull=True,
            )
            .order_by("-inserted_at")
            .first()
        )
        if existing:
            existing.scheduler_task_id = periodic_task.id
            existing.name = schedule_label
            existing.scheduled_at = scheduled_at
            existing.state = StateChoices.SCHEDULED
            existing.save(
                update_fields=["scheduler_task_id", "name", "scheduled_at", "state"]
            )
            return existing

        scheduled_scan = Scan.objects.create(
            tenant_id=tenant_id,
            name=schedule_label,
            provider_id=provider_id,
            trigger=Scan.TriggerChoices.SCHEDULED,
            state=StateChoices.SCHEDULED,
            scheduled_at=scheduled_at,
            scheduler_task_id=periodic_task.id,
        )
        attack_paths_db_utils.create_attack_paths_scan(
            tenant_id=tenant_id,
            scan_id=str(scheduled_scan.id),
            provider_id=provider_id,
        )
        return scheduled_scan


def sync_provider_scan_schedule(
    *,
    tenant_id: str,
    provider: Provider,
    scan_enabled: bool,
    scan_frequency: str,
    scan_hour: int | None,
    scan_timezone: str,
    scan_interval_hours: int | None,
    scan_day_of_week: int | None,
    scan_day_of_month: int | None,
) -> dict:
    """Create, update, pause, or remove the beat task for a provider.

    Returns:
        Public schedule attributes for the JSON:API resource.
    """
    provider_id = str(provider.id)
    task_name = periodic_task_name(provider_id)

    if not scan_enabled:
        _disable_periodic_task(task_name)
        PeriodicTask.objects.filter(name=task_name).delete()
        with rls_transaction(tenant_id):
            Scan.objects.filter(
                tenant_id=tenant_id,
                provider_id=provider_id,
                trigger=Scan.TriggerChoices.SCHEDULED,
                state__in=(StateChoices.AVAILABLE, StateChoices.SCHEDULED),
                task__isnull=True,
            ).update(state=StateChoices.CANCELLED)
        return _disabled_attributes(scan_timezone)

    frequency = (scan_frequency or "").upper()
    if frequency not in SCAN_FREQUENCIES:
        raise ScanScheduleError(f"Unsupported scan_frequency: {scan_frequency}")

    if scan_hour is None or not (0 <= int(scan_hour) <= 23):
        raise ScanScheduleError("scan_hour must be an integer from 0 to 23.")

    hour = int(scan_hour)
    tz_name = validate_timezone(scan_timezone)
    kwargs = json.dumps({"tenant_id": tenant_id, "provider_id": provider_id})

    if frequency == "INTERVAL":
        interval_hours = int(scan_interval_hours or 0)
        if interval_hours < MIN_INTERVAL_HOURS:
            raise ScanScheduleError(
                f"scan_interval_hours must be at least {MIN_INTERVAL_HOURS}."
            )
        interval, _ = IntervalSchedule.objects.get_or_create(
            every=interval_hours,
            period=IntervalSchedule.HOURS,
        )
        periodic_task, _ = PeriodicTask.objects.update_or_create(
            name=task_name,
            defaults={
                "task": CELERY_TASK,
                "interval": interval,
                "crontab": None,
                "kwargs": kwargs,
                "one_off": False,
                "enabled": True,
                "start_time": datetime.now(UTC) + timedelta(hours=interval_hours),
            },
        )
        label = f"Every {interval_hours}h scheduled scan"
    else:
        day_of_week = "*"
        day_of_month = "*"
        if frequency == "WEEKLY":
            if scan_day_of_week is None or not (0 <= int(scan_day_of_week) <= 6):
                raise ScanScheduleError("scan_day_of_week must be 0–6 (Sunday–Saturday).")
            day_of_week = str(int(scan_day_of_week))
        elif frequency == "MONTHLY":
            if scan_day_of_month is None or not (1 <= int(scan_day_of_month) <= 28):
                raise ScanScheduleError("scan_day_of_month must be 1–28.")
            day_of_month = str(int(scan_day_of_month))

        crontab = _get_or_create_crontab(
            minute="0",
            hour=str(hour),
            day_of_month=day_of_month,
            month_of_year="*",
            day_of_week=day_of_week,
            tz_name=tz_name,
        )
        periodic_task, _ = PeriodicTask.objects.update_or_create(
            name=task_name,
            defaults={
                "task": CELERY_TASK,
                "crontab": crontab,
                "interval": None,
                "kwargs": kwargs,
                "one_off": False,
                "enabled": True,
                "start_time": None,
            },
        )
        label = f"{frequency.title()} scheduled scan"

    _ensure_available_scan(
        tenant_id=tenant_id,
        provider_id=provider_id,
        periodic_task=periodic_task,
        schedule_label=label,
    )

    return {
        "scan_enabled": True,
        "scan_frequency": frequency,
        "scan_hour": hour,
        "scan_timezone": tz_name,
        "scan_interval_hours": (
            int(scan_interval_hours) if frequency == "INTERVAL" else None
        ),
        "scan_day_of_week": (
            int(scan_day_of_week) if frequency == "WEEKLY" else None
        ),
        "scan_day_of_month": (
            int(scan_day_of_month) if frequency == "MONTHLY" else None
        ),
        "next_scan_at": None,
        "last_scan_at": None,
    }


def _disabled_attributes(scan_timezone: str) -> dict:
    return {
        "scan_enabled": False,
        "scan_frequency": "DAILY",
        "scan_hour": None,
        "scan_timezone": validate_timezone(scan_timezone),
        "scan_interval_hours": None,
        "scan_day_of_week": None,
        "scan_day_of_month": None,
        "next_scan_at": None,
        "last_scan_at": None,
    }


def _run_times(task: PeriodicTask) -> dict:
    """``next_scan_at`` / ``last_scan_at`` for a provider's beat task."""
    now = datetime.now(UTC)
    if task.interval_id and task.start_time and task.start_time > now:
        next_run = task.start_time
    else:
        anchor = task.last_run_at or now
        next_run = advance_past_now(task, next_run_after(task, anchor))
    return {
        "next_scan_at": next_run.isoformat(),
        "last_scan_at": task.last_run_at.isoformat() if task.last_run_at else None,
    }


def read_schedule_attributes(provider: Provider) -> dict:
    """Derive schedule attributes from the beat task, if any."""
    task = PeriodicTask.objects.filter(
        name=periodic_task_name(str(provider.id)), enabled=True
    ).first()
    if not task:
        return _disabled_attributes("UTC")

    run_times = _run_times(task)

    if task.interval_id:
        return {
            "scan_enabled": True,
            "scan_frequency": "INTERVAL",
            "scan_hour": 0,
            "scan_timezone": "UTC",
            "scan_interval_hours": task.interval.every,
            "scan_day_of_week": None,
            "scan_day_of_month": None,
            **run_times,
        }

    crontab = task.crontab
    if not crontab:
        return _disabled_attributes("UTC")

    try:
        hour = int(str(crontab.hour).split(",")[0])
    except (TypeError, ValueError):
        hour = 0

    day_of_week = str(crontab.day_of_week)
    day_of_month = str(crontab.day_of_month)
    if day_of_week not in {"*", "*/1"}:
        frequency = "WEEKLY"
        dow = int(day_of_week.split(",")[0])
        dom = None
    elif day_of_month not in {"*", "*/1"}:
        frequency = "MONTHLY"
        dow = None
        dom = int(day_of_month.split(",")[0])
    else:
        frequency = "DAILY"
        dow = None
        dom = None

    return {
        "scan_enabled": True,
        "scan_frequency": frequency,
        "scan_hour": hour,
        "scan_timezone": str(crontab.timezone or "UTC"),
        "scan_interval_hours": None,
        "scan_day_of_week": dow,
        "scan_day_of_month": dom,
        **run_times,
    }


def remove_provider_scan_schedule(*, tenant_id: str, provider: Provider) -> None:
    sync_provider_scan_schedule(
        tenant_id=tenant_id,
        provider=provider,
        scan_enabled=False,
        scan_frequency="DAILY",
        scan_hour=None,
        scan_timezone="UTC",
        scan_interval_hours=None,
        scan_day_of_week=None,
        scan_day_of_month=None,
    )
