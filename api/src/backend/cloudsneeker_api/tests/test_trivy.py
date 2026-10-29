"""Trivy Hub validation, import mapping, enqueue wiring, and API surface."""

from __future__ import annotations

import json
import os
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
    normalize_repository_url,
    run_trivy_cli,
    scrub_secrets,
    validate_target_config,
)
from cloudsneeker_api.services.trivy_import import trivy_results_to_finding_rows
from cloudsneeker_api.views_trivy import TrivyTargetViewSet


def _iac_provider(secret: dict) -> MagicMock:
    provider = MagicMock()
    provider.provider = "iac"
    provider.secret.secret = secret
    return provider


class TestTrivyModes:
    def test_includes_full_surface(self):
        assert TRIVY_MODES == {
            "iac",
            "image",
            "fs",
            "repo",
            "sbom",
            "k8s",
            "sast",
        }
        assert PROWLER_SCAN_MODES == {"iac", "image"}
        assert is_valid_trivy_mode("sbom")
        assert not is_valid_trivy_mode("docker")

    def test_provider_type_guards(self):
        assert MODE_PROVIDER_TYPES["iac"] == {"iac"}
        assert MODE_PROVIDER_TYPES["image"] == {"image"}
        assert MODE_PROVIDER_TYPES["k8s"] == {"kubernetes"}
        # CLI-imported scans become their provider's latest scan, so they must
        # never attach to a cloud account (they would hide its real results).
        assert MODE_PROVIDER_TYPES["fs"] == {"iac"}
        assert MODE_PROVIDER_TYPES["repo"] == {"iac"}
        assert MODE_PROVIDER_TYPES["sbom"] == {"iac"}
        assert MODE_PROVIDER_TYPES["sast"] == {"iac"}


class TestValidateTargetConfig:
    def test_repo_requires_url(self):
        with pytest.raises(TrivyHubError, match="repository_url"):
            validate_target_config("repo", {})

    def test_sbom_requires_payload(self):
        with pytest.raises(TrivyHubError, match="sbom"):
            validate_target_config("sbom", {})

    def test_fs_requires_archive(self):
        with pytest.raises(TrivyHubError, match="config.archive_b64 is required"):
            validate_target_config("fs", {})

    def test_fs_rejects_worker_path(self):
        with pytest.raises(TrivyHubError, match="config.path is not supported"):
            validate_target_config("fs", {"path": "/etc"})

    def test_fs_archive_ok_and_blank_path_dropped(self):
        cfg = validate_target_config("fs", {"archive_b64": "UEsDBA==", "path": ""})
        assert cfg["archive_b64"] == "UEsDBA=="
        assert "path" not in cfg

    @pytest.mark.parametrize(
        "url",
        [
            "https://user:tok@github.com/acme/app",
            "https://ghp_token@github.com/acme/app",
            "https://x-token-auth:tok@bitbucket.org/acme/app.git",
            "https://user:pat@dev.azure.com/acme/p/_git/app",
            "https://other@dev.azure.com/acme/p/_git/app",
        ],
    )
    def test_repo_rejects_embedded_credentials(self, url):
        with pytest.raises(TrivyHubError, match="must not contain credentials"):
            validate_target_config("repo", {"repository_url": url})

    def test_repo_allows_azure_devops_org_userinfo(self):
        url = "https://acme@dev.azure.com/acme/p/_git/app"
        cfg = validate_target_config("repo", {"repository_url": url})
        assert cfg["repository_url"] == url

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

    def test_rejects_cloud_accounts_for_cli_modes(self):
        provider = MagicMock()
        provider.provider = "aws"
        for mode in ("fs", "repo", "sbom"):
            with pytest.raises(TrivyHubError, match="requires provider type"):
                assert_provider_matches_mode(provider, mode)

    def test_allows_iac_for_cli_modes(self):
        provider = MagicMock()
        provider.provider = "iac"
        for mode in ("fs", "repo", "sbom"):
            assert_provider_matches_mode(provider, mode)

    @pytest.mark.parametrize(
        "url",
        [
            "https://github.com/acme/app",
            "https://github.com/acme/app/",
            "https://github.com/acme/app.git",
            "https://GitHub.com/acme/app.git/",
        ],
    )
    def test_repo_url_must_match_provider_uid(self, url):
        provider = MagicMock()
        provider.provider = "iac"
        provider.uid = "https://github.com/acme/app.git"
        assert_provider_matches_mode(provider, "repo", {"repository_url": url})

    def test_repo_url_for_another_repository_is_rejected(self):
        provider = MagicMock()
        provider.provider = "iac"
        provider.uid = "https://github.com/acme/app"
        with pytest.raises(TrivyHubError, match="must match the linked IaC provider"):
            assert_provider_matches_mode(
                provider, "repo", {"repository_url": "https://evil.example/acme/app"}
            )

    def test_normalize_repository_url(self):
        assert (
            normalize_repository_url("https://acme@dev.azure.com/acme/p/_git/app/")
            == "https://dev.azure.com/acme/p/_git/app"
        )


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

    def test_fs_command_never_scans_a_worker_path(self, tmp_path):
        with patch(
            "cloudsneeker_api.services.trivy._resolve_trivy_bin",
            return_value="trivy",
        ):
            with pytest.raises(TrivyHubError, match="archive_b64"):
                build_trivy_command(
                    mode="fs",
                    config={"path": "/etc", "scanners": ["vuln"]},
                    provider=MagicMock(),
                    work_dir=tmp_path,
                )

    def test_github_repo_keeps_token_env(self, tmp_path):
        provider = _iac_provider({"access_token": "tok-1"})
        with patch(
            "cloudsneeker_api.services.trivy._resolve_trivy_bin",
            return_value="trivy",
        ):
            argv, env = build_trivy_command(
                mode="repo",
                config={"repository_url": "https://github.com/acme/app"},
                provider=provider,
                work_dir=tmp_path,
            )
        assert argv[-1] == "https://github.com/acme/app"
        assert env["GITHUB_TOKEN"] == "tok-1"
        assert env["GITLAB_TOKEN"] == "tok-1"

    @pytest.mark.parametrize(
        ("url", "secret", "expected"),
        [
            (
                "https://bitbucket.org/acme/app.git",
                {"access_token": "app-pass", "username": "jane"},
                "https://jane:app-pass@bitbucket.org/acme/app.git",
            ),
            (
                "https://dev.azure.com/acme/p/_git/app",
                {"access_token": "pat-1"},
                "https://pat:pat-1@dev.azure.com/acme/p/_git/app",
            ),
            (
                "https://git.acme.com/team/app.git",
                {"access_token": "tok-2"},
                "https://x-access-token:tok-2@git.acme.com/team/app.git",
            ),
        ],
    )
    def test_other_hosts_get_authenticated_url(self, tmp_path, url, secret, expected):
        clean_env = {
            key: value
            for key, value in os.environ.items()
            if key not in ("GITHUB_TOKEN", "GITLAB_TOKEN")
        }
        with (
            patch(
                "cloudsneeker_api.services.trivy._resolve_trivy_bin",
                return_value="trivy",
            ),
            patch.dict("os.environ", clean_env, clear=True),
        ):
            argv, env = build_trivy_command(
                mode="repo",
                config={"repository_url": url},
                provider=_iac_provider(secret),
                work_dir=tmp_path,
            )
        assert argv[-1] == expected
        assert "GITHUB_TOKEN" not in env
        assert "GITLAB_TOKEN" not in env


class TestRunTrivyCliRedaction:
    URL = "https://bitbucket.org/acme/app.git"
    TOKEN = "super-secret-token"

    def _run(self, process):
        provider = _iac_provider({"access_token": self.TOKEN})
        with (
            patch(
                "cloudsneeker_api.services.trivy._resolve_trivy_bin",
                return_value="trivy",
            ),
            patch(
                "cloudsneeker_api.services.trivy.subprocess.run",
                return_value=process,
            ) as mock_run,
        ):
            report = run_trivy_cli(
                mode="repo",
                config={"repository_url": self.URL, "scanners": ["vuln"]},
                provider=provider,
            )
        return report, mock_run

    def test_report_never_contains_token(self):
        auth_url = f"https://x-token-auth:{self.TOKEN}@bitbucket.org/acme/app.git"
        process = MagicMock(
            stdout=json.dumps(
                {"ArtifactName": auth_url, "Results": [{"Target": auth_url}]}
            ),
            stderr="",
            returncode=0,
        )
        report, mock_run = self._run(process)
        assert auth_url in mock_run.call_args.args[0]
        assert self.TOKEN not in json.dumps(report)

    def test_stderr_error_never_contains_token(self):
        process = MagicMock(
            stdout="",
            stderr=(
                "fatal: could not read "
                f"https://x-token-auth:{self.TOKEN}@bitbucket.org/acme/app.git"
            ),
            returncode=1,
        )
        with pytest.raises(TrivyHubError) as exc_info:
            self._run(process)
        assert self.TOKEN not in str(exc_info.value)
        assert "could not read" in str(exc_info.value)

    def test_subprocess_failure_never_contains_token(self):
        provider = _iac_provider({"access_token": self.TOKEN})
        with (
            patch(
                "cloudsneeker_api.services.trivy._resolve_trivy_bin",
                return_value="trivy",
            ),
            patch(
                "cloudsneeker_api.services.trivy.subprocess.run",
                side_effect=OSError(f"exec failed for {self.TOKEN}"),
            ),
        ):
            with pytest.raises(TrivyHubError) as exc_info:
                run_trivy_cli(
                    mode="repo",
                    config={"repository_url": self.URL},
                    provider=provider,
                )
        assert self.TOKEN not in str(exc_info.value)

    def test_scrub_secrets_walks_nested_values(self):
        value = {"a": ["x tok y", {"tok": 1}], "b": 2}
        assert scrub_secrets(value, ("tok",)) == {
            "a": ["x *** y", {"***": 1}],
            "b": 2,
        }

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
        target.provider.provider = "iac"
        target.provider.uid = "https://github.com/acme/app.git"

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
