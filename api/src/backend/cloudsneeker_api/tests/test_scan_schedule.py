"""Unit tests for provider scan schedule beat sync and the ``/schedules`` API."""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from cloudsneeker_api.services.scan_schedule import (
    ScanScheduleError,
    advance_past_now,
    next_run_after,
    periodic_task_name,
    read_schedule_attributes,
    scheduled_scan_window,
    sync_provider_scan_schedule,
)
from django.urls import reverse
from freezegun import freeze_time
from rest_framework import status


@pytest.mark.django_db
class TestScanScheduleSync:
    def test_rejects_unknown_frequency(self):
        provider = MagicMock()
        provider.id = "11111111-1111-1111-1111-111111111111"
        with pytest.raises(ScanScheduleError, match="Unsupported"):
            sync_provider_scan_schedule(
                tenant_id="22222222-2222-2222-2222-222222222222",
                provider=provider,
                scan_enabled=True,
                scan_frequency="YEARLY",
                scan_hour=9,
                scan_timezone="UTC",
                scan_interval_hours=None,
                scan_day_of_week=None,
                scan_day_of_month=None,
            )

    def test_task_name_uses_provider_id(self):
        assert periodic_task_name("abc") == "scan-perform-scheduled-abc"

    def test_daily_schedule_creates_crontab_task(self):
        provider = MagicMock()
        provider.id = "11111111-1111-1111-1111-111111111111"
        periodic = MagicMock()
        periodic.id = 42

        with (
            patch(
                "cloudsneeker_api.services.scan_schedule.PeriodicTask.objects.update_or_create",
                return_value=(periodic, True),
            ) as update_or_create,
            patch(
                "cloudsneeker_api.services.scan_schedule._ensure_available_scan",
            ),
            patch(
                "cloudsneeker_api.services.scan_schedule._get_or_create_crontab",
                return_value=MagicMock(),
            ),
        ):
            result = sync_provider_scan_schedule(
                tenant_id="22222222-2222-2222-2222-222222222222",
                provider=provider,
                scan_enabled=True,
                scan_frequency="DAILY",
                scan_hour=9,
                scan_timezone="UTC",
                scan_interval_hours=None,
                scan_day_of_week=None,
                scan_day_of_month=None,
            )

        assert result["scan_enabled"] is True
        assert result["scan_frequency"] == "DAILY"
        assert result["scan_hour"] == 9
        update_or_create.assert_called_once()


def _primary_data(response):
    """Return the primary data, unwrapping the renderer's ``data`` envelope."""
    body = response.json()["data"]
    while isinstance(body, dict) and "data" in body:
        body = body["data"]
    return body


@pytest.mark.django_db
class TestScheduleViewSetDocuments:
    """The ``/schedules`` routes accept the JSON:API types the UI sends."""

    def test_patch_accepts_schedules_type(self, authenticated_client, aws_provider):
        attributes = {
            "scan_enabled": True,
            "scan_frequency": "DAILY",
            "scan_hour": 9,
            "scan_timezone": "UTC",
        }
        with patch(
            "cloudsneeker_api.views_schedules.sync_provider_scan_schedule",
            return_value=attributes,
        ) as mock_sync:
            response = authenticated_client.patch(
                reverse("schedule-detail", kwargs={"pk": aws_provider.id}),
                data=json.dumps(
                    {
                        "data": {
                            "type": "schedules",
                            "id": str(aws_provider.id),
                            "attributes": attributes,
                        }
                    }
                ),
                content_type="application/vnd.api+json",
            )

        assert response.status_code == status.HTTP_200_OK
        assert _primary_data(response)["type"] == "schedules"
        assert mock_sync.call_args.kwargs["scan_frequency"] == "DAILY"

    def test_bulk_accepts_schedules_bulk_type(
        self, authenticated_client, aws_provider
    ):
        with patch(
            "cloudsneeker_api.views_schedules.sync_provider_scan_schedule"
        ) as mock_sync:
            response = authenticated_client.post(
                reverse("schedule-bulk"),
                data=json.dumps(
                    {
                        "data": {
                            "type": "schedules-bulk",
                            "attributes": {
                                "schedule": {
                                    "scan_enabled": True,
                                    "scan_frequency": "WEEKLY",
                                    "scan_hour": 6,
                                    "scan_day_of_week": 1,
                                },
                                "provider_ids": [str(aws_provider.id)],
                            },
                        }
                    }
                ),
                content_type="application/vnd.api+json",
            )

        assert response.status_code == status.HTTP_200_OK
        assert mock_sync.call_count == 1
        assert str(aws_provider.id) in json.dumps(response.json())

    def test_list_returns_visible_providers(self, authenticated_client, aws_provider):
        response = authenticated_client.get(reverse("schedule-list"))

        assert response.status_code == status.HTTP_200_OK
        ids = {item["id"] for item in _primary_data(response)}
        assert str(aws_provider.id) in ids

    def test_list_is_a_single_wrapped_document(
        self, authenticated_client, aws_provider
    ):
        # The UI spreads ``result.data``; a nested ``data.data`` object broke it.
        response = authenticated_client.get(reverse("schedule-list"))

        body = response.json()
        assert isinstance(body["data"], list)
        assert body["data"][0]["type"] == "schedules"
        assert body["meta"]["pagination"]["page"] == 1

    def test_list_accepts_the_configured_filter(
        self, authenticated_client, aws_provider
    ):
        response = authenticated_client.get(
            reverse("schedule-list"), {"filter[configured]": "true"}
        )

        assert response.status_code == status.HTTP_200_OK
        assert isinstance(response.json()["data"], list)

    def test_list_includes_providers_and_paginates(
        self, authenticated_client, aws_provider
    ):
        response = authenticated_client.get(
            reverse("schedule-list"),
            {"include": "provider", "page[size]": "1", "page[number]": "1"},
        )

        body = response.json()
        assert len(body["data"]) == 1
        assert body["included"][0]["type"] == "providers"
        assert body["included"][0]["id"] == body["data"][0]["id"]
        assert body["meta"]["pagination"]["pages"] == body["meta"]["pagination"]["count"]


def _crontab_task(hour="9", day_of_week="*", tz="UTC"):
    from django_celery_beat.models import CrontabSchedule

    task = MagicMock()
    task.interval_id = None
    task.interval = None
    task.crontab_id = 7
    task.crontab = CrontabSchedule(
        minute="0",
        hour=hour,
        day_of_month="*",
        month_of_year="*",
        day_of_week=day_of_week,
        timezone=tz,
    )
    return task


def _interval_task(hours=24):
    task = MagicMock()
    task.crontab_id = None
    task.crontab = None
    task.interval_id = 3
    task.interval.period = "hours"
    task.interval.every = hours
    return task


class TestCrontabAwareScheduling:
    @freeze_time("2026-10-28 15:30:00", tz_offset=0)
    def test_next_run_after_daily_crontab_is_the_next_fire_time(self):
        after = datetime(2026, 10, 28, 15, 30, tzinfo=UTC)
        assert next_run_after(_crontab_task(hour="9"), after) == datetime(
            2026, 10, 29, 9, 0, tzinfo=UTC
        )

    @freeze_time("2026-10-28 15:30:00", tz_offset=0)
    def test_next_run_after_weekly_crontab_respects_the_day(self):
        after = datetime(2026, 10, 28, 15, 30, tzinfo=UTC)  # Wednesday
        # day_of_week 1 = Monday in celery crontab
        assert next_run_after(_crontab_task(day_of_week="1"), after) == datetime(
            2026, 11, 2, 9, 0, tzinfo=UTC
        )

    @freeze_time("2026-10-28 15:30:00", tz_offset=0)
    def test_next_run_after_reads_the_crontab_in_its_own_timezone(self):
        # 21:00 Asia/Kolkata is 15:30 UTC; just after it, the next run is tomorrow.
        after = datetime(2026, 10, 28, 16, 0, tzinfo=UTC)
        task = _crontab_task(hour="21", tz="Asia/Kolkata")
        assert next_run_after(task, after) == datetime(
            2026, 10, 29, 15, 30, tzinfo=UTC
        )

    def test_next_run_after_interval_adds_the_interval(self):
        after = datetime(2026, 10, 28, 15, 30, tzinfo=UTC)
        assert next_run_after(_interval_task(48), after) == after + timedelta(
            hours=48
        )

    @freeze_time("2026-10-28 15:30:00", tz_offset=0)
    def test_scheduled_scan_window_for_crontab_runs_now(self):
        upstream_next = MagicMock()
        next_dt, current_dt = scheduled_scan_window(
            _crontab_task(hour="9"), upstream_next
        )

        assert current_dt == datetime(2026, 10, 28, 15, 30, tzinfo=UTC)
        assert next_dt == datetime(2026, 10, 29, 9, 0, tzinfo=UTC)
        upstream_next.assert_not_called()

    def test_scheduled_scan_window_for_interval_keeps_upstream_math(self):
        upstream = datetime(2026, 10, 29, 15, 0, tzinfo=UTC)
        next_dt, current_dt = scheduled_scan_window(
            _interval_task(24), lambda: upstream
        )

        assert next_dt == upstream
        assert current_dt == upstream - timedelta(hours=24)

    @freeze_time("2026-10-28 15:30:00", tz_offset=0)
    def test_advance_past_now_skips_missed_crontab_runs(self):
        stale = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
        assert advance_past_now(_crontab_task(hour="9"), stale) == datetime(
            2026, 10, 29, 9, 0, tzinfo=UTC
        )

    @freeze_time("2026-10-28 15:30:00", tz_offset=0)
    def test_read_schedule_attributes_reports_the_next_run(self):
        task = _crontab_task(hour="9")
        task.last_run_at = None
        with patch(
            "cloudsneeker_api.services.scan_schedule.PeriodicTask.objects.filter"
        ) as mock_filter:
            mock_filter.return_value.first.return_value = task
            provider = MagicMock()
            provider.id = "11111111-1111-1111-1111-111111111111"
            attrs = read_schedule_attributes(provider)

        assert attrs["scan_frequency"] == "DAILY"
        assert attrs["next_scan_at"] == "2026-10-29T09:00:00+00:00"
        assert attrs["last_scan_at"] is None

    def test_unscheduled_task_is_rejected(self):
        task = MagicMock()
        task.interval_id = None
        task.crontab_id = None
        with pytest.raises(ScanScheduleError):
            next_run_after(task, datetime(2026, 10, 28, tzinfo=UTC))
