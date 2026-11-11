"""Application Security scan history: latest runs per target and archiving."""

from __future__ import annotations

from datetime import timedelta

import pytest
from api.db_utils import rls_transaction
from api.models import Provider
from cloudsneeker_api.models import TrivyRun, TrivyTarget
from cloudsneeker_api.services import trivy_history
from django.urls import reverse
from django.utils import timezone


def _target(provider, name: str) -> TrivyTarget:
    return TrivyTarget.objects.create(
        tenant_id=provider.tenant_id, name=name, mode="repo", provider=provider
    )


def _run(target: TrivyTarget, *, days_ago: float = 0) -> TrivyRun:
    run = TrivyRun.objects.create(
        tenant_id=target.tenant_id,
        target=target,
        provider=target.provider,
        status=TrivyRun.Status.COMPLETED,
    )
    if days_ago:
        with rls_transaction(str(target.tenant_id)):
            TrivyRun.objects.filter(id=run.id).update(
                inserted_at=timezone.now() - timedelta(days=days_ago)
            )
    return run


def _ids(response) -> list[str]:
    assert response.status_code == 200, response.content
    return [item["id"] for item in response.json()["data"]]


@pytest.fixture
def repo_provider(provider_factory):
    return provider_factory(
        Provider.ProviderChoices.IAC.value,
        uid="https://bitbucket.org/acme/web.git",
    )


class TestArchiveDays:
    def test_default_is_one_year(self, monkeypatch):
        monkeypatch.delenv("APP_SECURITY_SCAN_ARCHIVE_DAYS", raising=False)
        assert trivy_history.archive_days() == 365

    @pytest.mark.parametrize(
        "value,expected", [("30", 30), ("0", 365), ("-4", 365), ("soon", 365)]
    )
    def test_env_override(self, monkeypatch, value, expected):
        monkeypatch.setenv("APP_SECURITY_SCAN_ARCHIVE_DAYS", value)
        assert trivy_history.archive_days() == expected


@pytest.mark.django_db
class TestArchiveRuns:
    def test_archives_only_runs_past_the_window(self, repo_provider):
        target = _target(repo_provider, "acme/web")
        old = _run(target, days_ago=400)
        fresh = _run(target, days_ago=10)

        archived = trivy_history.archive_all_tenants([str(target.tenant_id)], 365)

        assert archived == 1
        with rls_transaction(str(target.tenant_id)):
            old.refresh_from_db()
            fresh.refresh_from_db()
        assert old.archived_at is not None
        assert fresh.archived_at is None

    def test_keeps_the_first_archive_time(self, repo_provider):
        target = _target(repo_provider, "acme/web")
        _run(target, days_ago=400)
        trivy_history.archive_all_tenants([str(target.tenant_id)], 365)

        assert trivy_history.archive_all_tenants([str(target.tenant_id)], 365) == 0

    def test_migration_registers_the_daily_task(self):
        import importlib

        from django.apps import apps
        from django_celery_beat.models import PeriodicTask

        migration = importlib.import_module(
            "cloudsneeker_api.migrations.0022_trivy_run_archive"
        )
        migration.create_periodic_task(apps, None)
        migration.create_periodic_task(apps, None)  # idempotent

        task = PeriodicTask.objects.get(name=migration.TASK_NAME)
        assert task.task == "cloudsneeker-archive-trivy-runs"
        assert task.enabled
        assert task.interval.every == 1 and task.interval.period == "days"

    def test_task_name_is_registered_with_celery(self):
        from cloudsneeker_api.tasks import archive_trivy_runs_task

        assert archive_trivy_runs_task.name == "cloudsneeker-archive-trivy-runs"


@pytest.mark.django_db
class TestRunHistoryFilters:
    def test_archived_filter(self, authenticated_client, repo_provider):
        target = _target(repo_provider, "acme/web")
        old = _run(target, days_ago=400)
        fresh = _run(target)
        trivy_history.archive_all_tenants([str(target.tenant_id)], 365)
        url = reverse("trivy-runs-list")

        assert _ids(authenticated_client.get(url, {"filter[archived]": "false"})) == [
            str(fresh.id)
        ]
        assert _ids(authenticated_client.get(url, {"filter[archived]": "true"})) == [
            str(old.id)
        ]
        # Without the filter the list is unchanged: every run.
        assert len(_ids(authenticated_client.get(url))) == 2

    def test_archived_at_is_returned(self, authenticated_client, repo_provider):
        target = _target(repo_provider, "acme/web")
        _run(target, days_ago=400)
        trivy_history.archive_all_tenants([str(target.tenant_id)], 365)

        response = authenticated_client.get(reverse("trivy-runs-list"))

        assert response.json()["data"][0]["attributes"]["archived_at"]

    def test_latest_per_target(self, authenticated_client, repo_provider):
        web = _target(repo_provider, "acme/web")
        api = _target(repo_provider, "acme/api")
        web_runs = [_run(web, days_ago=days) for days in (5, 4, 3, 2, 1)]
        api_run = _run(api, days_ago=6)

        ids = _ids(
            authenticated_client.get(
                reverse("trivy-runs-list"),
                {"filter[latest_per_target]": "3", "page[size]": "100"},
            )
        )

        newest_web = [str(run.id) for run in reversed(web_runs[2:])]
        assert ids == [*newest_web, str(api_run.id)]

    def test_latest_per_target_skips_archived_runs(
        self, authenticated_client, repo_provider
    ):
        target = _target(repo_provider, "acme/web")
        _run(target, days_ago=400)
        fresh = _run(target, days_ago=1)
        trivy_history.archive_all_tenants([str(target.tenant_id)], 365)

        ids = _ids(
            authenticated_client.get(
                reverse("trivy-runs-list"),
                {"filter[latest_per_target]": "20", "filter[archived]": "false"},
            )
        )

        assert ids == [str(fresh.id)]

    @pytest.mark.parametrize("value", ["0", "101", "many"])
    def test_latest_per_target_rejects_bad_values(self, authenticated_client, value):
        response = authenticated_client.get(
            reverse("trivy-runs-list"), {"filter[latest_per_target]": value}
        )

        assert response.status_code == 400

    def test_mode_filter(self, authenticated_client, repo_provider):
        repo_run = _run(_target(repo_provider, "web-repo"))
        sast = TrivyTarget.objects.create(
            tenant_id=repo_provider.tenant_id,
            name="web-sast",
            mode="sast",
            provider=repo_provider,
        )
        sast_run = _run(sast)
        url = reverse("trivy-runs-list")

        assert _ids(authenticated_client.get(url, {"filter[mode]": "sast"})) == [
            str(sast_run.id)
        ]
        assert _ids(authenticated_client.get(url, {"filter[mode]": "repo"})) == [
            str(repo_run.id)
        ]
