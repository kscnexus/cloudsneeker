"""Report schedule sync to Celery Beat and scheduled generation + email."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from api.db_utils import rls_transaction
from cloudsneeker_api.models import ReportRun, ReportSchedule
from cloudsneeker_api.reports.schedule import (
    PERIODIC_TASK_PREFIX,
    SCHEDULED_TASK_NAME,
    ReportScheduleError,
    delete_report_schedule_task,
    periodic_task_name,
    run_scheduled_report,
    sync_report_schedule,
)
from cloudsneeker_api.task_permissions import cloudsneeker_task_revoke_permissions
from django.test import override_settings
from django_celery_beat.models import PeriodicTask


@pytest.fixture
def report_dir(tmp_path):
    with override_settings(DJANGO_TMP_OUTPUT_DIRECTORY=str(tmp_path)):
        yield tmp_path


def _schedule(tenant, **overrides) -> ReportSchedule:
    values = {
        "name": "weekly-exec",
        "report_type": "executive",
        "params": {},
        "formats": ["pdf", "json"],
        "schedule_cron": "0 8 * * 1",
        "schedule_timezone": "UTC",
        "recipients": ["ciso@example.com"],
        "enabled": True,
        **overrides,
    }
    with rls_transaction(str(tenant.id)):
        return ReportSchedule.objects.create(tenant_id=tenant.id, **values)


@pytest.mark.django_db
class TestScheduleSync:
    def test_enable_creates_periodic_task(self, tenants_fixture):
        tenant = tenants_fixture[0]
        schedule = _schedule(tenant)
        with rls_transaction(str(tenant.id)):
            sync_report_schedule(schedule)
        task = PeriodicTask.objects.get(name=periodic_task_name(str(schedule.id)))
        assert task.name.startswith(PERIODIC_TASK_PREFIX)
        assert task.task == SCHEDULED_TASK_NAME
        assert task.enabled is True
        assert str(schedule.id) in task.kwargs and str(tenant.id) in task.kwargs
        assert (task.crontab.minute, task.crontab.hour, task.crontab.day_of_week) == (
            "0",
            "8",
            "1",
        )
        assert schedule.scheduler_task_id == task.id
        assert schedule.next_run_at is not None

    def test_resync_updates_same_task(self, tenants_fixture):
        tenant = tenants_fixture[0]
        schedule = _schedule(tenant)
        with rls_transaction(str(tenant.id)):
            sync_report_schedule(schedule)
            schedule.schedule_cron = "30 6 * * *"
            sync_report_schedule(schedule)
        tasks = PeriodicTask.objects.filter(name=periodic_task_name(str(schedule.id)))
        assert tasks.count() == 1
        assert tasks.first().crontab.hour == "6"

    def test_disable_and_delete(self, tenants_fixture):
        tenant = tenants_fixture[0]
        schedule = _schedule(tenant)
        with rls_transaction(str(tenant.id)):
            sync_report_schedule(schedule)
            schedule.enabled = False
            sync_report_schedule(schedule)
        task = PeriodicTask.objects.get(name=periodic_task_name(str(schedule.id)))
        assert task.enabled is False
        assert schedule.scheduler_task_id is None
        assert schedule.next_run_at is None
        delete_report_schedule_task(str(schedule.id))
        assert not PeriodicTask.objects.filter(name=task.name).exists()

    def test_disable_without_task_is_noop(self, tenants_fixture):
        tenant = tenants_fixture[0]
        schedule = _schedule(tenant, enabled=False)
        with rls_transaction(str(tenant.id)):
            sync_report_schedule(schedule)
        assert not PeriodicTask.objects.filter(
            name=periodic_task_name(str(schedule.id))
        ).exists()

    @pytest.mark.parametrize(
        "overrides", [{"schedule_cron": "bad"}, {"schedule_timezone": "Nowhere/City"}]
    )
    def test_invalid_input_raises(self, tenants_fixture, overrides):
        tenant = tenants_fixture[0]
        schedule = _schedule(tenant, **overrides)
        with pytest.raises(ReportScheduleError):
            with rls_transaction(str(tenant.id)):
                sync_report_schedule(schedule)


@pytest.mark.django_db
class TestRunScheduledReport:
    def test_skips_missing_and_disabled(self, tenants_fixture):
        tenant = tenants_fixture[0]
        missing = run_scheduled_report(
            tenant_id=str(tenant.id), schedule_id="00000000-0000-4000-8000-000000000000"
        )
        assert missing["status"] == "skipped"
        disabled = _schedule(tenant, enabled=False)
        assert (
            run_scheduled_report(tenant_id=str(tenant.id), schedule_id=str(disabled.id))[
                "status"
            ]
            == "skipped"
        )

    def test_generates_and_emails(self, tenants_fixture, report_dir):
        tenant = tenants_fixture[0]
        schedule = _schedule(tenant)
        with patch(
            "cloudsneeker_api.reports.delivery.deliver_report_email",
            return_value={"delivery": "attachment", "sent": 1},
        ) as deliver:
            result = run_scheduled_report(
                tenant_id=str(tenant.id), schedule_id=str(schedule.id)
            )
        assert result["status"] == "completed"
        assert result["delivery"] == "attachment"
        kwargs = deliver.call_args.kwargs
        assert kwargs["recipients"] == ["ciso@example.com"]
        run = kwargs["run"]
        assert run.status == ReportRun.Status.COMPLETED
        assert run.trigger == ReportRun.Trigger.SCHEDULED
        assert run.schedule_id == schedule.id
        assert "pdf" in run.artifacts
        with rls_transaction(str(tenant.id)):
            schedule.refresh_from_db()
        assert schedule.last_run_id == run.id
        assert schedule.last_run_at is not None
        assert schedule.next_run_at is not None

    def test_failed_generation_skips_email(self, tenants_fixture, report_dir):
        tenant = tenants_fixture[0]
        schedule = _schedule(tenant)
        with (
            patch(
                "cloudsneeker_api.reports.runs.assemble_report",
                side_effect=RuntimeError("db down"),
            ),
            patch("cloudsneeker_api.reports.delivery.deliver_report_email") as deliver,
        ):
            result = run_scheduled_report(
                tenant_id=str(tenant.id), schedule_id=str(schedule.id)
            )
        assert result["status"] == "failed"
        deliver.assert_not_called()

    def test_beat_task_delegates(self):
        from cloudsneeker_api.tasks import scheduled_report_task

        with patch(
            "cloudsneeker_api.reports.schedule.run_scheduled_report",
            return_value={"status": "skipped"},
        ) as runner:
            result = scheduled_report_task.run.__wrapped__(tenant_id="t", schedule_id="s")
        runner.assert_called_once_with(tenant_id="t", schedule_id="s")
        assert result == {"status": "skipped"}


class TestTaskPermissions:
    def test_report_tasks_are_registered(self):
        class _Permissions:
            MANAGE_SCANS = "manage_scans"

        mapping = cloudsneeker_task_revoke_permissions(_Permissions)
        assert mapping["cloudsneeker-generate-report"] == []
        assert mapping["cloudsneeker-scheduled-report"] == ["manage_scans"]
