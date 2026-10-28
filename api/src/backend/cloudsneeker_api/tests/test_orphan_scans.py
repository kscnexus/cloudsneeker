"""Unit tests for failing scans whose Celery worker is gone."""

from unittest.mock import MagicMock, patch

from api.db_router import MainRouter
from api.models import StateChoices
from celery import states
from cloudsneeker_api.services.orphan_scans import (
    ORPHAN_ERROR,
    PING_ATTEMPTS,
    RELAUNCH_MARKER,
    fail_orphaned_scans,
    fail_orphaned_scans_all_tenants,
)

MODULE = "cloudsneeker_api.services.orphan_scans"
TENANT_ID = "22222222-2222-2222-2222-222222222222"


def _scan(
    scan_id="scan-1", provider_id="provider-1", worker="celery@gone", scanner_args=None
):
    scan = MagicMock()
    scan.id = scan_id
    scan.provider_id = provider_id
    scan.state = StateChoices.EXECUTING
    scan.scanner_args = scanner_args or {}
    scan.task.task_runner_task.worker = worker
    scan.task.task_runner_task.status = states.STARTED
    return scan


def _run(candidates, alive=False, queued=None):
    queryset = MagicMock()
    queryset.select_related.return_value.order_by.return_value = candidates
    with (
        patch(f"{MODULE}.rls_transaction") as mock_rls,
        patch(f"{MODULE}.Scan.objects.filter", return_value=queryset),
        patch(f"{MODULE}.is_worker_alive", return_value=alive) as mock_alive,
        patch(
            "tasks.tasks._dispatch_next_queued_provider_scan", return_value=queued
        ) as mock_dispatch,
        patch(f"{MODULE}._relaunch_scan") as mock_relaunch,
    ):
        mock_rls.return_value.__enter__ = MagicMock()
        mock_rls.return_value.__exit__ = MagicMock(return_value=False)
        failed = fail_orphaned_scans(TENANT_ID)
    return failed, mock_alive, mock_dispatch, mock_relaunch


class TestFailOrphanedScans:
    def test_fails_scan_and_relaunches_when_nothing_is_queued(self):
        scan = _scan()

        failed, mock_alive, mock_dispatch, mock_relaunch = _run([scan])

        assert failed == ["scan-1"]
        assert scan.state == StateChoices.FAILED
        scan.save.assert_called_once()
        task_result = scan.task.task_runner_task
        assert task_result.status == states.FAILURE
        assert task_result.result == ORPHAN_ERROR
        assert mock_alive.call_count == PING_ATTEMPTS
        mock_dispatch.assert_called_once_with(TENANT_ID, "provider-1")
        mock_relaunch.assert_called_once_with(TENANT_ID, scan)

    def test_dispatches_queued_scan_instead_of_relaunching(self):
        scan = _scan()

        failed, _, mock_dispatch, mock_relaunch = _run([scan], queued=MagicMock())

        assert failed == ["scan-1"]
        mock_dispatch.assert_called_once_with(TENANT_ID, "provider-1")
        mock_relaunch.assert_not_called()

    def test_never_relaunches_a_relaunched_scan(self):
        scan = _scan(scanner_args={RELAUNCH_MARKER: "older-scan"})

        failed, _, _, mock_relaunch = _run([scan])

        assert failed == ["scan-1"]
        mock_relaunch.assert_not_called()

    def test_leaves_trivy_hub_scans_to_the_hub(self):
        scan = _scan(scanner_args={"source": "trivy_hub", "mode": "image"})

        failed, _, _, mock_relaunch = _run([scan])

        assert failed == ["scan-1"]
        mock_relaunch.assert_not_called()

    def test_leaves_scan_alone_when_worker_still_answers(self):
        scan = _scan()

        failed, _, mock_dispatch, mock_relaunch = _run([scan], alive=True)

        assert failed == []
        assert scan.state == StateChoices.EXECUTING
        scan.save.assert_not_called()
        mock_dispatch.assert_not_called()
        mock_relaunch.assert_not_called()

    def test_skips_tasks_without_a_recorded_worker(self):
        scan = _scan(worker=None)

        failed, mock_alive, mock_dispatch, _ = _run([scan])

        assert failed == []
        mock_alive.assert_not_called()
        mock_dispatch.assert_not_called()

    def test_resume_errors_do_not_hide_failed_scans(self):
        scan = _scan()
        queryset = MagicMock()
        queryset.select_related.return_value.order_by.return_value = [scan]
        with (
            patch(f"{MODULE}.rls_transaction") as mock_rls,
            patch(f"{MODULE}.Scan.objects.filter", return_value=queryset),
            patch(f"{MODULE}.is_worker_alive", return_value=False),
            patch(
                "tasks.tasks._dispatch_next_queued_provider_scan",
                side_effect=RuntimeError("broker down"),
            ),
        ):
            mock_rls.return_value.__enter__ = MagicMock()
            mock_rls.return_value.__exit__ = MagicMock(return_value=False)
            failed = fail_orphaned_scans(TENANT_ID)

        assert failed == ["scan-1"]
        assert scan.state == StateChoices.FAILED


class TestFailOrphanedScansAllTenants:
    def test_noops_when_another_sweep_holds_the_lock(self):
        with (
            patch(f"{MODULE}.advisory_lock") as mock_lock,
            patch(f"{MODULE}.fail_orphaned_scans") as mock_fail,
        ):
            mock_lock.return_value.__enter__ = MagicMock(return_value=False)
            mock_lock.return_value.__exit__ = MagicMock(return_value=False)
            result = fail_orphaned_scans_all_tenants()

        assert result == {"acquired": False, "failed_scans": []}
        mock_fail.assert_not_called()

    def test_sweeps_every_tenant(self):
        with (
            patch(f"{MODULE}.advisory_lock") as mock_lock,
            patch("api.models.Tenant.objects.using") as mock_using,
            patch(
                f"{MODULE}.fail_orphaned_scans", side_effect=[["s-1"], []]
            ) as mock_fail,
        ):
            mock_lock.return_value.__enter__ = MagicMock(return_value=True)
            mock_lock.return_value.__exit__ = MagicMock(return_value=False)
            mock_using.return_value.values_list.return_value = ["t-1", "t-2"]
            result = fail_orphaned_scans_all_tenants()

        assert result == {"acquired": True, "failed_scans": ["s-1"]}
        assert mock_fail.call_count == 2
        # RLS hides tenants from the app role, so the sweep must use admin.
        mock_using.assert_called_once_with(MainRouter.admin_db)
