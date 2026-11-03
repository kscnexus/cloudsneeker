"""Content versions panel (EB-048)."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from cloudsneeker_api.services import content_versions as service
from cloudsneeker_api.services import vuln_db
from django.urls import reverse

NOW = datetime(2026, 11, 4, 12, 0, tzinfo=UTC)


def _snapshot(root: Path, refreshed_at: datetime, published: str | None = None):
    def run(argv, **kwargs):
        cache = Path(argv[argv.index("--cache-dir") + 1])
        if argv[-1] == "--download-db-only":
            (cache / "db").mkdir(parents=True)
            (cache / "db" / "trivy.db").write_bytes(b"db")
            (cache / "db" / "metadata.json").write_text(
                json.dumps({"Version": 2, "UpdatedAt": published})
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    with patch.object(vuln_db.subprocess, "run", side_effect=run):
        return vuln_db.refresh(root, trivy_bin="trivy", now=refreshed_at)


class TestVulnerabilityDatabase:
    def test_fresh_snapshot(self, tmp_path, monkeypatch):
        monkeypatch.setenv(vuln_db.CACHE_DIR_ENV, str(tmp_path))
        _snapshot(
            tmp_path,
            NOW - timedelta(hours=3),
            published="2026-11-04T06:13:59.123456789Z",
        )
        state = service.vulnerability_database(NOW)
        assert state == {
            "status": "fresh",
            "refreshed_at": "2026-11-04T09:00:00Z",
            "published_at": "2026-11-04T06:13:59.123456Z",
            "age_hours": 3.0,
            "max_age_hours": 24,
            "java_db": False,
        }

    def test_stale_snapshot(self, tmp_path, monkeypatch):
        monkeypatch.setenv(vuln_db.CACHE_DIR_ENV, str(tmp_path))
        _snapshot(tmp_path, NOW - timedelta(hours=30))
        state = service.vulnerability_database(NOW)
        assert state["status"] == "stale"
        assert state["age_hours"] == 30.0
        assert state["published_at"] is None

    def test_missing_snapshot(self, tmp_path, monkeypatch):
        monkeypatch.setenv(vuln_db.CACHE_DIR_ENV, str(tmp_path))
        state = service.vulnerability_database(NOW)
        assert state["status"] == "missing"
        assert state["refreshed_at"] is None

    def test_not_configured(self, monkeypatch):
        monkeypatch.delenv(vuln_db.CACHE_DIR_ENV, raising=False)
        assert service.vulnerability_database(NOW)["status"] == "not_configured"


class TestVersions:
    def test_engines_come_from_the_image(self, monkeypatch):
        monkeypatch.setenv("TRIVY_VERSION", "0.74.0")
        monkeypatch.setenv("CLOUDSNEEKER_OPENGREP_VERSION", "1.30.2")
        monkeypatch.delenv("CLOUDSNEEKER_C7N_VERSION", raising=False)
        engines = {entry["id"]: entry for entry in service.engines()}
        assert engines["scanner"]["version"] == "0.74.0"
        assert engines["code_analyzer"]["version"] == "1.30.2"
        assert engines["governance"]["version"] is None
        assert engines["attack_paths"]["version"]

    def test_labels_do_not_name_engines(self):
        labels = " ".join(entry["label"] for entry in service.engines()).lower()
        for name in ("trivy", "opengrep", "custodian", "cartography", "zizmor"):
            assert name not in labels

    def test_code_analysis_rules(self, tmp_path, monkeypatch):
        (tmp_path / "python").mkdir()
        (tmp_path / "python" / "a.yml").write_text("rules: []")
        (tmp_path / "python" / "b.yaml").write_text("rules: []")
        (tmp_path / "python" / "README.md").write_text("")
        monkeypatch.setenv("CLOUDSNEEKER_SAST_RULES_REF", "v2.10.1")
        monkeypatch.setenv(service.RULES_DIR_ENV, str(tmp_path))
        service._rule_count.cache_clear()
        assert service.code_analysis_rules() == {"version": "v2.10.1", "rules": 2}

    def test_cloud_security_counts_checks_and_frameworks(self):
        content = service.cloud_security_content()
        assert content["version"]
        assert content["checks"] > 100
        assert content["frameworks"] > 10


@pytest.mark.django_db
class TestContentVersionsEndpoint:
    def test_returns_the_versions(self, authenticated_client, monkeypatch):
        monkeypatch.setenv(service.RELEASE_ENV, "abc123def456")
        monkeypatch.delenv(vuln_db.CACHE_DIR_ENV, raising=False)
        response = authenticated_client.get(reverse("content-versions"))
        assert response.status_code == 200, response.content
        data = response.json()["data"]
        assert data["type"] == "cloudsneeker-content-versions"
        assert data["id"] == "current"
        attributes = data["attributes"]
        assert attributes["release"] == "abc123def456"
        assert attributes["vulnerability_database"]["status"] == "not_configured"
        assert set(attributes) == {
            "release",
            "cloud_security",
            "vulnerability_database",
            "code_analysis_rules",
            "engines",
        }

    def test_requires_authentication(self, client):
        assert client.get(reverse("content-versions")).status_code == 401
