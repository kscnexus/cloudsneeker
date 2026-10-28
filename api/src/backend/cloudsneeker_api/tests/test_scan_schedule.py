"""Unit tests for provider scan schedule beat sync and the ``/schedules`` API."""

import json
from unittest.mock import MagicMock, patch

import pytest
from cloudsneeker_api.services.scan_schedule import (
    ScanScheduleError,
    periodic_task_name,
    sync_provider_scan_schedule,
)
from django.urls import reverse
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
