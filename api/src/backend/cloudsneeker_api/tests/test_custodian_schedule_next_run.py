"""Next fire time for Custodian and Trivy Hub cron schedules."""

from datetime import UTC, datetime

from cloudsneeker_api.services.custodian_schedule import compute_next_run_at

NOW = datetime(2026, 10, 28, 15, 30, tzinfo=UTC)  # Wednesday


class TestComputeNextRunAt:
    def test_daily_cron_moves_to_tomorrow_after_todays_slot(self):
        assert compute_next_run_at("0 9 * * *", "UTC", now=NOW) == datetime(
            2026, 10, 29, 9, 0, tzinfo=UTC
        )

    def test_never_returns_the_current_time(self):
        assert compute_next_run_at("0 9 * * *", "UTC", now=NOW) > NOW

    def test_same_day_slot_later_today(self):
        assert compute_next_run_at("0 18 * * *", "UTC", now=NOW) == datetime(
            2026, 10, 28, 18, 0, tzinfo=UTC
        )

    def test_weekly_cron_respects_day_of_week(self):
        # 1 = Monday
        assert compute_next_run_at("0 9 * * 1", "UTC", now=NOW) == datetime(
            2026, 11, 2, 9, 0, tzinfo=UTC
        )

    def test_timezone_is_applied_before_converting_to_utc(self):
        # 09:00 in Kolkata (UTC+5:30) is 03:30 UTC the next day.
        assert compute_next_run_at("0 9 * * *", "Asia/Kolkata", now=NOW) == datetime(
            2026, 10, 29, 3, 30, tzinfo=UTC
        )

    def test_every_fifteen_minutes(self):
        assert compute_next_run_at("*/15 * * * *", "UTC", now=NOW) == datetime(
            2026, 10, 28, 15, 45, tzinfo=UTC
        )
