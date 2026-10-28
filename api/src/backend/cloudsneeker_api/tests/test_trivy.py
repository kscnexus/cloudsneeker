"""Trivy Hub validation, import mapping, enqueue wiring, and API surface."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from cloudsneeker_api.models import JSON_API_TYPE_PREFIX, TrivyRun, TrivyTarget
from cloudsneeker_api.services.trivy import (
    MODE_PROVIDER_TYPES,
    PROWLER_SCAN_MODES,
    TRIVY_MODES,
    TrivyHubError,
    assert_provider_matches_mode,
    build_trivy_command,
    effective_run_status,
    enqueue_trivy_run,
    is_valid_trivy_mode,
    validate_target_config,
)
from cloudsneeker_api.services.trivy_import import trivy_results_to_finding_rows
from cloudsneeker_api.views_trivy import TrivyTargetViewSet


class TestTrivyModes:
    def test_includes_full_surface(self):
        assert TRIVY_MODES == {
            "iac",
            "image",
            "fs",
            "repo",
            "sbom",
            "k8s",
        }
        assert PROWLER_SCAN_MODES == {"iac", "image"}
        assert is_valid_trivy_mode("sbom")
        assert not is_valid_trivy_mode("docker")

    def test_provider_type_guards(self):
        assert MODE_PROVIDER_TYPES["iac"] == {"iac"}
        assert MODE_PROVIDER_TYPES["image"] == {"image"}
        assert MODE_PROVIDER_TYPES["k8s"] == {"kubernetes"}
        assert MODE_PROVIDER_TYPES["fs"] == frozenset()


class TestValidateTargetConfig:
    def test_repo_requires_url(self):
        with pytest.raises(TrivyHubError, match="repository_url"):
            validate_target_config("repo", {})

    def test_sbom_requires_payload(self):
        with pytest.raises(TrivyHubError, match="sbom"):
            validate_target_config("sbom", {})

    def test_fs_requires_path_or_archive(self):
        with pytest.raises(TrivyHubError, match="path or config.archive"):
            validate_target_config("fs", {})

    def test_defaults_scanners(self):
        cfg = validate_target_config("iac", {})
        assert cfg["scanners"] == ["vuln", "misconfig", "secret"]

    def test_repo_ok(self):
        cfg = validate_target_config(
            "repo", {"repository_url": "https://github.com/acme/app"}
        )
        assert cfg["repository_url"] == "https://github.com/acme/app"


class TestAssertProviderMatchesMode:
    def test_rejects_wrong_provider(self):
        provider = MagicMock()
        provider.provider = "aws"
        with pytest.raises(TrivyHubError, match="requires provider type"):
            assert_provider_matches_mode(provider, "iac")

    def test_allows_any_for_fs(self):
        provider = MagicMock()
        provider.provider = "aws"
        assert_provider_matches_mode(provider, "fs")


class TestTrivyImportMapping:
    def test_maps_vulnerabilities_and_misconfigurations(self):
        report = {
            "Results": [
                {
                    "Target": "app/package-lock.json",
                    "Class": "lang-pkgs",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1",
                            "PkgName": "left-pad",
                            "Severity": "HIGH",
                            "Title": "Issue",
                            "Description": "Bad package",
                        }
                    ],
                    "Misconfigurations": [
                        {
                            "ID": "AVD-1",
                            "Title": "Open SG",
                            "Severity": "CRITICAL",
                            "Status": "FAIL",
                            "Description": "Wide open",
                        }
                    ],
                    "Secrets": [
                        {
                            "RuleID": "aws-key",
                            "Title": "AWS key",
                            "Severity": "CRITICAL",
                            "Match": "AKIA...",
                        }
                    ],
                }
            ]
        }
        rows = trivy_results_to_finding_rows(report, mode="fs")
        assert len(rows) == 3
        assert rows[0]["check_id"] == "CVE-2024-1"
        assert rows[0]["severity"] == "high"
        assert rows[0]["status"] == "FAIL"
        assert rows[1]["check_id"] == "AVD-1"
        assert rows[1]["severity"] == "critical"
        assert rows[2]["check_id"] == "aws-key"


class TestBuildTrivyCommand:
    def test_repo_command(self, tmp_path):
        provider = MagicMock()
        provider.secret = None
        with patch(
            "cloudsneeker_api.services.trivy._resolve_trivy_bin",
            return_value="trivy",
        ):
            argv, env = build_trivy_command(
                mode="repo",
                config={
                    "repository_url": "https://github.com/acme/app",
                    "scanners": ["vuln"],
                },
                provider=provider,
                work_dir=tmp_path,
            )
        assert argv[:4] == ["trivy", "--quiet", "-f", "json"]
        assert "repo" in argv
        assert "https://github.com/acme/app" in argv

    def test_sbom_writes_file(self, tmp_path):
        provider = MagicMock()
        with patch(
            "cloudsneeker_api.services.trivy._resolve_trivy_bin",
            return_value="trivy",
        ):
            argv, _env = build_trivy_command(
                mode="sbom",
                config={"sbom": '{"bomFormat":"CycloneDX"}', "scanners": ["vuln"]},
                provider=provider,
                work_dir=tmp_path,
            )
        assert "sbom" in argv
        sbom_path = tmp_path / "sbom.json"
        assert sbom_path.exists()
        assert "CycloneDX" in sbom_path.read_text(encoding="utf-8")


class TestTrivyModelMeta:
    def test_jsonapi_and_tables(self):
        assert TrivyTarget.JSONAPIMeta.resource_name == (
            f"{JSON_API_TYPE_PREFIX}trivy-targets"
        )
        assert TrivyRun.JSONAPIMeta.resource_name == (
            f"{JSON_API_TYPE_PREFIX}trivy-runs"
        )
        assert TrivyTarget._meta.db_table == "cloudsneeker_trivy_targets"
        assert TrivyRun._meta.db_table == "cloudsneeker_trivy_runs"


class TestTrivyTargetViewSetWiring:
    def test_scan_action(self):
        mapping = TrivyTargetViewSet.scan.kwargs
        assert TrivyTargetViewSet.scan.url_path == "scan"
        parsers = mapping.get("parser_classes", [])
        assert parsers


class TestEnqueueTrivyRun:
    def test_creates_pending_and_schedules_task(self):
        target = MagicMock()
        target.id = "target-1"
        target.mode = "repo"
        target.config = {"repository_url": "https://github.com/acme/app"}
        target.provider = MagicMock()
        target.provider.provider = "aws"

        run = MagicMock()
        run.id = "run-1"

        mock_qs = MagicMock()
        mock_qs.select_related.return_value.get.return_value = target
        mock_runs = MagicMock()
        mock_runs.filter.return_value.count.return_value = 0
        mock_runs.create.return_value = run

        with (
            patch(
                "cloudsneeker_api.services.trivy.rls_transaction"
            ) as mock_rls,
            patch(
                "cloudsneeker_api.services.trivy.TrivyTarget.objects",
                mock_qs,
            ),
            patch(
                "cloudsneeker_api.services.trivy.TrivyRun.objects",
                mock_runs,
            ),
            patch(
                "cloudsneeker_api.services.trivy.transaction.on_commit"
            ) as mock_on_commit,
            patch(
                "cloudsneeker_api.tasks.trivy_scan_task"
            ) as mock_task,
        ):
            mock_rls.return_value.__enter__ = MagicMock()
            mock_rls.return_value.__exit__ = MagicMock(return_value=False)
            result = enqueue_trivy_run(
                tenant_id="tenant-1",
                target_id="target-1",
            )
            assert result is run
            mock_on_commit.assert_called_once()
            callback = mock_on_commit.call_args[0][0]
            callback()
            mock_task.delay.assert_called_once_with(
                tenant_id="tenant-1", run_id="run-1"
            )


class TestEffectiveRunStatus:
    @pytest.mark.parametrize(
        ("scan_state", "expected"),
        [
            ("available", "pending"),
            ("scheduled", "pending"),
            ("executing", "running"),
            ("completed", "completed"),
            ("failed", "failed"),
            ("cancelled", "failed"),
        ],
    )
    def test_provider_scan_runs_follow_the_linked_scan(self, scan_state, expected):
        assert (
            effective_run_status(
                TrivyRun.Status.COMPLETED,
                {"path": "provider_scan"},
                scan_state,
            )
            == expected
        )

    def test_cli_runs_keep_their_own_status(self):
        assert (
            effective_run_status(
                TrivyRun.Status.COMPLETED, {"path": "trivy_cli"}, "failed"
            )
            == TrivyRun.Status.COMPLETED
        )

    def test_missing_linked_scan_keeps_run_status(self):
        assert (
            effective_run_status(
                TrivyRun.Status.COMPLETED, {"path": "provider_scan"}, None
            )
            == TrivyRun.Status.COMPLETED
        )

    def test_failed_run_stays_failed(self):
        assert (
            effective_run_status(
                TrivyRun.Status.FAILED, {"path": "provider_scan"}, "completed"
            )
            == TrivyRun.Status.FAILED
        )
