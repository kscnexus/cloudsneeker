"""Shared vulnerability database cache (EB-047)."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cloudsneeker_api.services import vuln_db
from cloudsneeker_api.services.trivy import build_trivy_command
from cloudsneeker_api.tasks import refresh_vuln_db_task
from django.core.management import CommandError, call_command

NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)


def _fake_trivy(java_ok: bool = True, db_ok: bool = True):
    """Stand in for ``trivy image --download-*-only`` by writing the files."""

    def run(argv, **kwargs):
        cache = Path(argv[argv.index("--cache-dir") + 1])
        if argv[-1] == "--download-db-only":
            if not db_ok:
                return subprocess.CompletedProcess(argv, 1, "", "FATAL\nregistry down")
            (cache / "db").mkdir(parents=True)
            (cache / "db" / "trivy.db").write_bytes(b"db")
            (cache / "db" / "metadata.json").write_text("{}")
            return subprocess.CompletedProcess(argv, 0, "", "")
        if not java_ok:
            return subprocess.CompletedProcess(argv, 1, "", "java registry down")
        (cache / "java-db").mkdir(parents=True)
        (cache / "java-db" / "trivy-java.db").write_bytes(b"java")
        return subprocess.CompletedProcess(argv, 0, "", "")

    return run


def _refresh(root: Path, now: datetime = NOW, **fake) -> vuln_db.Snapshot:
    with patch.object(vuln_db.subprocess, "run", side_effect=_fake_trivy(**fake)):
        return vuln_db.refresh(root, trivy_bin="trivy", now=now)


class TestRefresh:
    def test_creates_a_snapshot_and_points_current_at_it(self, tmp_path):
        snapshot = _refresh(tmp_path)
        assert snapshot.java_db is True
        assert (tmp_path / "current").is_symlink()
        current = vuln_db.current_snapshot(tmp_path)
        assert current.path == snapshot.path.resolve()
        assert current.refreshed_at == NOW
        assert current.java_db is True

    def test_failed_download_keeps_the_previous_snapshot(self, tmp_path):
        first = _refresh(tmp_path)
        with pytest.raises(vuln_db.VulnDbError, match="registry down"):
            _refresh(tmp_path, now=NOW + timedelta(hours=6), db_ok=False)
        assert vuln_db.current_snapshot(tmp_path).path == first.path.resolve()
        assert len(list((tmp_path / "snapshots").iterdir())) == 1

    def test_java_failure_still_publishes_the_snapshot(self, tmp_path):
        snapshot = _refresh(tmp_path, java_ok=False)
        assert snapshot.java_db is False
        assert not (snapshot.path / "java-db").exists()
        assert vuln_db.current_snapshot(tmp_path).java_db is False

    def test_keeps_only_the_newest_snapshots(self, tmp_path):
        for hours in range(4):
            latest = _refresh(tmp_path, now=NOW + timedelta(hours=6 * hours))
        names = sorted(p.name for p in (tmp_path / "snapshots").iterdir())
        assert len(names) == vuln_db.KEEP_SNAPSHOTS
        assert names[-1] == latest.path.name

    def test_requires_a_configured_directory(self, monkeypatch):
        monkeypatch.delenv(vuln_db.CACHE_DIR_ENV, raising=False)
        with pytest.raises(vuln_db.VulnDbError, match="not set"):
            vuln_db.refresh(trivy_bin="trivy")


class TestScanCacheEnv:
    def test_fresh_snapshot_links_the_databases_and_skips_updates(self, tmp_path):
        root = tmp_path / "shared"
        snapshot = _refresh(root, now=datetime.now(UTC))
        work = tmp_path / "scan"
        env = vuln_db.scan_cache_env(work, root=root)
        cache = Path(env["TRIVY_CACHE_DIR"])
        assert cache.parent == work
        assert env["TRIVY_SKIP_DB_UPDATE"] == "true"
        assert env["TRIVY_SKIP_JAVA_DB_UPDATE"] == "true"
        assert (cache / "db" / "trivy.db").read_bytes() == b"db"
        assert (cache / "db").resolve() == (snapshot.path / "db").resolve()
        # The artifact cache stays private to the scan.
        assert not (cache / "fanal").exists()

    def test_no_java_db_lets_trivy_fetch_it(self, tmp_path):
        root = tmp_path / "shared"
        _refresh(root, now=datetime.now(UTC), java_ok=False)
        env = vuln_db.scan_cache_env(tmp_path / "scan", root=root)
        assert env["TRIVY_SKIP_DB_UPDATE"] == "true"
        assert "TRIVY_SKIP_JAVA_DB_UPDATE" not in env

    def test_stale_snapshot_falls_back_to_download(self, tmp_path):
        root = tmp_path / "shared"
        _refresh(root, now=datetime.now(UTC) - timedelta(hours=25))
        assert vuln_db.scan_cache_env(tmp_path / "scan", root=root) == {}

    def test_missing_cache_falls_back_to_download(self, tmp_path):
        assert vuln_db.scan_cache_env(tmp_path / "scan", root=tmp_path / "x") == {}

    def test_unconfigured_cache_falls_back_to_download(self, tmp_path, monkeypatch):
        monkeypatch.delenv(vuln_db.CACHE_DIR_ENV, raising=False)
        assert vuln_db.scan_cache_env(tmp_path) == {}

    def test_corrupt_marker_is_ignored(self, tmp_path):
        root = tmp_path / "shared"
        snapshot = _refresh(root, now=datetime.now(UTC))
        (snapshot.path / "snapshot.json").write_text("not json")
        assert vuln_db.scan_cache_env(tmp_path / "scan", root=root) == {}

    def test_direct_trivy_scans_use_the_shared_snapshot(self, tmp_path, monkeypatch):
        root = tmp_path / "shared"
        _refresh(root, now=datetime.now(UTC))
        monkeypatch.setenv(vuln_db.CACHE_DIR_ENV, str(root))
        work = tmp_path / "scan"
        work.mkdir()
        with patch(
            "cloudsneeker_api.services.trivy._resolve_trivy_bin",
            return_value="trivy",
        ):
            argv, env = build_trivy_command(
                mode="sbom",
                config={"sbom": json.dumps({"bomFormat": "CycloneDX"})},
                provider=MagicMock(),
                work_dir=work,
            )
        assert argv[-2] == "sbom"
        assert env["TRIVY_SKIP_DB_UPDATE"] == "true"
        assert Path(env["TRIVY_CACHE_DIR"]).parent == work


class TestEntrypoints:
    def test_task_skips_when_not_configured(self, monkeypatch):
        monkeypatch.delenv(vuln_db.CACHE_DIR_ENV, raising=False)
        assert refresh_vuln_db_task() == {
            "refreshed": False,
            "reason": "not configured",
        }

    def test_command_reports_the_current_snapshot(self, tmp_path, monkeypatch):
        _refresh(tmp_path, now=datetime.now(UTC))
        monkeypatch.setenv(vuln_db.CACHE_DIR_ENV, str(tmp_path))
        out = StringIO()
        call_command("cloudsneeker_vuln_db", stdout=out)
        assert "java_db=True" in out.getvalue()
        assert "Scans use the shared snapshot." in out.getvalue()

    def test_command_fails_on_a_stale_snapshot(self, tmp_path, monkeypatch):
        _refresh(tmp_path, now=datetime.now(UTC) - timedelta(days=2))
        monkeypatch.setenv(vuln_db.CACHE_DIR_ENV, str(tmp_path))
        with pytest.raises(CommandError, match="too old"):
            call_command("cloudsneeker_vuln_db", stdout=StringIO())

    def test_command_fails_without_a_snapshot(self, tmp_path, monkeypatch):
        monkeypatch.setenv(vuln_db.CACHE_DIR_ENV, str(tmp_path))
        with pytest.raises(CommandError, match="No usable snapshot"):
            call_command("cloudsneeker_vuln_db", stdout=StringIO())
