"""Unit tests for provider scan schedule beat sync."""

from unittest.mock import MagicMock, patch

import pytest
from cloudsneeker_api.services.scan_schedule import (
    ScanScheduleError,
    periodic_task_name,
    sync_provider_scan_schedule,
)


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
