"""ASPM scan engine: workspace, process control, retries, masking, options.

No database: the process tests run a real child process (the Python
interpreter standing in for the scanner); the rest use fakes.
"""

from __future__ import annotations

import base64
import gzip
import io
import json
import sys
import tarfile
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from cloudsneeker_api.appsec import engine, failures, inventory, lifecycle
from cloudsneeker_api.appsec.options import OptionError
from cloudsneeker_api.appsec.parser import (
    NormalizedComponent,
    NormalizedFinding,
    parse_report,
)
from cloudsneeker_api.appsec.shared_rows import remediation_text, shared_row
from cloudsneeker_api.services.trivy import TrivyHubError, validate_target_config

LIMITS = {
    **engine.engine_limits(),
    "max_attempts": 3,
    "default_timeout_seconds": 900,
}


def _zip(files: dict[str, bytes]) -> str:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return base64.b64encode(buffer.getvalue()).decode()


def _tar(build) -> str:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        build(archive)
    return base64.b64encode(buffer.getvalue()).decode()


def _add(archive, name: str, content: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    archive.addfile(info, io.BytesIO(content))


class TestSafeExtract:
    def test_extracts_zip_and_tar(self, tmp_path):
        root = engine.safe_extract(_zip({"app/package.json": b"{}"}), tmp_path)
        assert (root / "app" / "package.json").read_bytes() == b"{}"
        assert not (tmp_path / "upload.bin").exists()
        other = tmp_path / "t"
        other.mkdir()
        root = engine.safe_extract(
            _tar(lambda a: _add(a, "go.mod", b"module x")), other
        )
        assert (root / "go.mod").read_text() == "module x"

    @pytest.mark.parametrize("name", ["../evil.txt", "a/../../evil.txt", "/etc/passwd"])
    def test_rejects_paths_outside_the_root(self, tmp_path, name):
        with pytest.raises(engine.EngineError, match="outside its root"):
            engine.safe_extract(_zip({name: b"x"}), tmp_path)
        with pytest.raises(engine.EngineError, match="outside its root"):
            engine.safe_extract(_tar(lambda a: _add(a, name, b"x")), tmp_path)
        assert not (tmp_path.parent / "evil.txt").exists()

    def test_links_are_not_extracted(self, tmp_path):
        def build(archive):
            link = tarfile.TarInfo("link")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            archive.addfile(link)
            _add(archive, "ok.txt", b"ok")

        root = engine.safe_extract(_tar(build), tmp_path)
        assert sorted(path.name for path in root.iterdir()) == ["ok.txt"]

    def test_limits(self, tmp_path):
        many = _zip({f"f{index}.txt": b"x" for index in range(5)})
        with pytest.raises(engine.EngineError, match="too many files"):
            engine.safe_extract(many, tmp_path, {**LIMITS, "max_extracted_files": 3})
        big = _zip({"big.bin": b"0" * 5000})
        with pytest.raises(engine.EngineError, match="expands beyond"):
            engine.safe_extract(big, tmp_path, {**LIMITS, "max_extracted_bytes": 1024})
        with pytest.raises(engine.EngineError, match="upload size limit"):
            engine.safe_extract(big, tmp_path, {**LIMITS, "max_archive_bytes": 10})
        with pytest.raises(engine.EngineError, match="not a readable"):
            engine.safe_extract(base64.b64encode(b"not an archive").decode(), tmp_path)


class TestEnvironment:
    def test_platform_secrets_are_not_inherited(self, monkeypatch):
        monkeypatch.setenv("POSTGRES_PASSWORD", "db-secret")
        monkeypatch.setenv("DJANGO_SECRETS_ENCRYPTION_KEY", "key")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws")
        monkeypatch.setenv("TRIVY_DB_REPOSITORY", "mirror/trivy-db")
        monkeypatch.setenv("TRIVY_PASSWORD", "stale")
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy:3128")
        env = engine.base_environment()
        assert "POSTGRES_PASSWORD" not in env
        assert "DJANGO_SECRETS_ENCRYPTION_KEY" not in env
        assert "AWS_SECRET_ACCESS_KEY" not in env
        assert "TRIVY_PASSWORD" not in env
        assert env["TRIVY_DB_REPOSITORY"] == "mirror/trivy-db"
        assert env["HTTPS_PROXY"] == "http://proxy:3128"
        assert "PATH" in env

    def test_direct_modes_switch(self, monkeypatch):
        monkeypatch.delenv("APPSEC_ENGINE_DIRECT_MODES", raising=False)
        assert {"iac", "image", "repo", "k8s", "sbom", "fs", "rootfs"} == set(
            engine.direct_modes()
        )
        monkeypatch.setenv("APPSEC_ENGINE_DIRECT_MODES", "repo, fs, bogus")
        assert engine.direct_modes() == {"repo", "fs"}


def _script(tmp_path: Path, body: str) -> list[str]:
    path = tmp_path / "fake_scanner.py"
    path.write_text(body, encoding="utf-8")
    return [sys.executable, str(path)]


class TestRunProcess:
    def _run(self, tmp_path, argv, *, timeout=30, is_cancelled=lambda: False):
        return engine.run_process(
            argv,
            env=engine.base_environment(),
            cwd=tmp_path,
            timeout=timeout,
            is_cancelled=is_cancelled,
            stdout_path=tmp_path / "out.json",
            stderr_path=tmp_path / "err.log",
        )

    def test_stdout_and_stderr_are_captured_apart(self, tmp_path):
        argv = _script(
            tmp_path,
            "import sys\nsys.stdout.write('{\"ok\": true}')\n"
            "sys.stderr.write('INFO scanning')\nsys.exit(0)\n",
        )
        result = self._run(tmp_path, argv)
        assert result.exit_code == 0 and not result.timed_out and not result.cancelled
        assert json.loads(result.stdout_path.read_text()) == {"ok": True}
        assert result.stderr == "INFO scanning"

    def test_exit_code_is_reported(self, tmp_path):
        result = self._run(tmp_path, _script(tmp_path, "import sys\nsys.exit(3)\n"))
        assert result.exit_code == 3

    def test_timeout_kills_the_process(self, tmp_path, monkeypatch):
        monkeypatch.setattr(engine, "POLL_SECONDS", 0.1)
        result = self._run(
            tmp_path, _script(tmp_path, "import time\ntime.sleep(60)\n"), timeout=0
        )
        assert result.timed_out and not result.cancelled
        assert result.duration_ms < 20000

    def test_cancellation_kills_the_process(self, tmp_path, monkeypatch):
        monkeypatch.setattr(engine, "POLL_SECONDS", 0.1)
        result = self._run(
            tmp_path,
            _script(tmp_path, "import time\ntime.sleep(60)\n"),
            is_cancelled=lambda: True,
        )
        assert result.cancelled and not result.timed_out


REPORT = {
    "SchemaVersion": 2,
    "Trivy": {"Version": "0.74.0"},
    "ArtifactName": "https://x-token:tok-123@git.example.com/acme/shop",
    "ArtifactType": "repository",
    "Results": [
        {
            "Target": ".env",
            "Class": "secret",
            "Secrets": [
                {
                    "RuleID": "generic",
                    "Severity": "HIGH",
                    "Title": "Password",
                    "StartLine": 1,
                    "EndLine": 1,
                    "Match": "password=plaintext-leak",
                    "Code": {
                        "Lines": [
                            {
                                "Number": 1,
                                "Content": "password=plaintext-leak",
                                "IsCause": True,
                            }
                        ]
                    },
                }
            ],
        }
    ],
}


def _process_result(
    tmp_path, *, exit_code=0, stderr="", report=None, timed_out=False, cancelled=False
):
    def fake(argv, *, stdout_path, stderr_path, **_kwargs):
        stdout_path.write_text(
            json.dumps(report) if report is not None else "", encoding="utf-8"
        )
        return engine.ProcessResult(
            exit_code=exit_code,
            timed_out=timed_out,
            cancelled=cancelled,
            stdout_path=stdout_path,
            stderr=stderr,
            duration_ms=5,
        )

    return fake


class TestRunUnit:
    def _unit(self, **kwargs):
        return engine.ScanUnit(
            "repository",
            "https://x-token:tok-123@git.example.com/acme/shop",
            label="https://git.example.com/acme/shop",
            secrets=("tok-123", "https://x-token:tok-123@git.example.com/acme/shop"),
            **kwargs,
        )

    def _run(self, tmp_path, side_effect, **kwargs):
        sleeps: list[float] = []
        with (
            patch.object(engine, "run_process", side_effect=side_effect) as process,
            patch("cloudsneeker_api.services.vuln_db.scan_cache_env", return_value={}),
        ):
            outcome = engine.run_unit(
                unit=self._unit(),
                index=0,
                mode="repo",
                options={"scanners": ["vuln", "secret"], "timeout_seconds": 300},
                policy_items=kwargs.get("policy_items", []),
                work_dir=tmp_path,
                artifact_dir=tmp_path / "artifacts",
                limits=LIMITS,
                is_cancelled=kwargs.get("is_cancelled", lambda: False),
                binary="/usr/local/bin/trivy",
                sleep=sleeps.append,
            )
        return outcome, process, sleeps

    def test_success_parses_masks_and_stores(self, tmp_path):
        outcome, process, _ = self._run(
            tmp_path, _process_result(tmp_path, report=REPORT)
        )
        assert outcome.failure is None and outcome.attempts == 1
        argv = process.call_args.args[0]
        assert argv[:2] == ["/usr/local/bin/trivy", "repository"]
        assert argv[-1].endswith("/acme/shop")
        assert argv[argv.index("--timeout") + 1] == "300s"
        assert process.call_args.kwargs["timeout"] == 360
        # The stored command, report and findings carry no credential.
        assert "tok-123" not in json.dumps(outcome.command)
        with gzip.open(tmp_path / "artifacts" / outcome.artifact, "rt") as handle:
            stored = handle.read()
        assert "tok-123" not in stored and "plaintext-leak" not in stored
        (finding,) = outcome.parsed.findings
        assert "plaintext-leak" not in json.dumps(finding.details) + json.dumps(
            finding.raw
        )

    def test_database_failure_is_retried_with_backoff(self, tmp_path):
        calls = iter(
            [
                _process_result(
                    tmp_path,
                    exit_code=1,
                    stderr="FATAL failed to download vulnerability DB",
                ),
                _process_result(
                    tmp_path,
                    exit_code=1,
                    stderr="FATAL failed to download vulnerability DB",
                ),
                _process_result(tmp_path, report=REPORT),
            ]
        )
        outcome, process, sleeps = self._run(
            tmp_path, lambda *args, **kwargs: next(calls)(*args, **kwargs)
        )
        assert outcome.failure is None and outcome.attempts == 3
        assert process.call_count == 3
        assert sum(sleeps) >= 15

    def test_retries_stop_at_the_limit(self, tmp_path):
        outcome, process, _ = self._run(
            tmp_path,
            _process_result(
                tmp_path,
                exit_code=1,
                stderr="FATAL failed to download vulnerability DB",
            ),
        )
        assert process.call_count == 3
        assert (
            outcome.failure.kind == failures.FAILURE_DATABASE and outcome.parsed is None
        )

    def test_registry_rate_limit_retries_at_once_offline(self, tmp_path):
        rate_limited = (
            "FATAL Error remote Maven repository returned 429 Too Many Requests "
            "for https://repo.maven.apache.org/maven2/org/x/x.pom. Retry-After: 1157."
        )
        calls = iter(
            [
                _process_result(tmp_path, exit_code=1, stderr=rate_limited),
                _process_result(tmp_path, report=REPORT),
            ]
        )
        outcome, process, sleeps = self._run(
            tmp_path, lambda *args, **kwargs: next(calls)(*args, **kwargs)
        )
        assert outcome.failure is None and outcome.offline_fallback is True
        assert process.call_count == 2 and sleeps == []
        first, second = (call.args[0] for call in process.call_args_list)
        assert engine.OFFLINE_FLAG not in first
        assert second[:3] == [
            "/usr/local/bin/trivy",
            "repository",
            engine.OFFLINE_FLAG,
        ]
        assert engine.OFFLINE_FLAG in outcome.command

    def test_registry_rate_limit_falls_back_only_once(self, tmp_path):
        outcome, process, _ = self._run(
            tmp_path,
            _process_result(
                tmp_path,
                exit_code=1,
                stderr="FATAL npm registry returned 429 Too Many Requests",
            ),
        )
        assert process.call_count == 2
        assert outcome.failure.kind == failures.FAILURE_RATE_LIMITED

    def test_auth_failure_is_not_retried_and_is_redacted(self, tmp_path):
        outcome, process, _ = self._run(
            tmp_path,
            _process_result(
                tmp_path,
                exit_code=1,
                stderr="FATAL repository scan error: authentication required for https://x-token:tok-123@git.example.com/acme/shop",
            ),
        )
        assert process.call_count == 1
        assert outcome.failure.kind == failures.FAILURE_AUTH
        assert outcome.exit_code == 1
        assert "tok-123" not in outcome.stderr_tail

    def test_timeout_and_cancel(self, tmp_path):
        outcome, _, _ = self._run(
            tmp_path, _process_result(tmp_path, exit_code=None, timed_out=True)
        )
        assert outcome.failure.kind == failures.FAILURE_TIMEOUT
        outcome, _, _ = self._run(
            tmp_path, _process_result(tmp_path, exit_code=None, cancelled=True)
        )
        assert outcome.failure.kind == failures.FAILURE_CANCELLED

    @pytest.mark.parametrize("payload", ["", "{not json", "[1, 2]"])
    def test_unreadable_report_fails_the_unit(self, tmp_path, payload):
        def fake(argv, *, stdout_path, stderr_path, **_kwargs):
            stdout_path.write_text(payload, encoding="utf-8")
            return engine.ProcessResult(0, False, False, stdout_path, "", 1)

        outcome, _, _ = self._run(tmp_path, fake)
        assert (
            outcome.failure.kind == failures.FAILURE_OUTPUT and outcome.parsed is None
        )

    def test_policy_flags_reach_the_command(self, tmp_path):
        items = [
            {
                "id": "1",
                "kind": "ignore_rules",
                "name": "i",
                "version": 1,
                "content": "vulnerabilities:\n  - id: CVE-1\n",
            }
        ]
        _, process, _ = self._run(
            tmp_path, _process_result(tmp_path, report=REPORT), policy_items=items
        )
        argv = process.call_args.args[0]
        assert Path(argv[argv.index("--ignorefile") + 1]).is_file()


class TestMaskReport:
    def test_masks_plain_and_cluster_reports(self):
        cluster = {"ClusterName": "c", "Resources": [{"Results": REPORT["Results"]}]}
        for report in (json.loads(json.dumps(REPORT)), json.loads(json.dumps(cluster))):
            assert "plaintext-leak" not in json.dumps(engine.mask_report(report))


def _provider(uid="https://git.example.com/acme/shop", secret=None, kind="iac"):
    provider = MagicMock()
    provider.uid = uid
    provider.provider = kind
    provider.secret.secret = secret or {}
    return provider


class TestPrepareUnits:
    def test_repository_over_https(self, tmp_path):
        provider = _provider(secret={"access_token": "tok-123"})
        (unit,) = engine.prepare_units(
            mode="repo",
            config={"repository_url": "https://git.example.com/acme/shop"},
            provider=provider,
            work_dir=tmp_path,
            limits=LIMITS,
        )
        assert unit.subcommand == "repository"
        assert "tok-123" in unit.secrets
        assert unit.label == "https://git.example.com/acme/shop"

    def test_infrastructure_target_uses_the_provider_repository(self, tmp_path):
        (unit,) = engine.prepare_units(
            mode="iac",
            config={},
            provider=_provider(),
            work_dir=tmp_path,
            limits=LIMITS,
        )
        assert unit.subcommand == "repository"
        assert unit.target_arg == "https://git.example.com/acme/shop"

    def test_archive_targets(self, tmp_path):
        config = {"archive_b64": _zip({"a.txt": b"x"})}
        for mode, command in (("fs", "filesystem"), ("rootfs", "rootfs")):
            work = tmp_path / mode
            work.mkdir()
            (unit,) = engine.prepare_units(
                mode=mode,
                config=config,
                provider=_provider(),
                work_dir=work,
                limits=LIMITS,
            )
            assert unit.subcommand == command
            assert Path(unit.target_arg).is_dir()

    def test_sbom_format_is_detected(self, tmp_path):
        cdx = json.dumps(
            {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
        )
        (unit,) = engine.prepare_units(
            mode="sbom",
            config={"sbom": cdx},
            provider=_provider(),
            work_dir=tmp_path,
            limits=LIMITS,
        )
        assert unit.sbom_format == "cyclonedx" and unit.target_arg.endswith(".cdx.json")
        (unit,) = engine.prepare_units(
            mode="sbom",
            config={"sbom": "SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\n"},
            provider=_provider(),
            work_dir=tmp_path,
            limits=LIMITS,
        )
        assert unit.sbom_format == "spdx" and unit.target_arg.endswith(".spdx")
        with pytest.raises(engine.EngineError, match="not CycloneDX"):
            engine.prepare_units(
                mode="sbom",
                config={"sbom": "<bom/>"},
                provider=_provider(),
                work_dir=tmp_path,
                limits=LIMITS,
            )

    def test_images(self, tmp_path):
        provider = _provider(
            uid="registry.example.com/team/app:1.0",
            secret={"registry_username": "ci", "registry_password": "pw-9"},
            kind="image",
        )
        (unit,) = engine.prepare_units(
            mode="image", config={}, provider=provider, work_dir=tmp_path, limits=LIMITS
        )
        assert unit.target_arg == "registry.example.com/team/app:1.0"
        assert unit.env == {"TRIVY_USERNAME": "ci", "TRIVY_PASSWORD": "pw-9"}
        assert unit.secrets == ("pw-9",) and unit.scope == ""
        units = engine.prepare_units(
            mode="image",
            config={
                "images": [
                    "registry.example.com/team/app:1.0",
                    "registry.example.com:5000/team/db@sha256:abc",
                ]
            },
            provider=provider,
            work_dir=tmp_path,
            limits=LIMITS,
        )
        assert [unit.scope for unit in units] == [
            "registry.example.com/team/app",
            "registry.example.com:5000/team/db",
        ]
        with pytest.raises(engine.EngineError, match="at most 1 images"):
            engine.prepare_units(
                mode="image",
                config={"images": ["a:1", "b:1"]},
                provider=provider,
                work_dir=tmp_path,
                limits={**LIMITS, "max_images_per_run": 1},
            )

    def test_registry_wide_detection(self):
        assert engine.is_registry_wide("registry.example.com", {}) is True
        assert (
            engine.is_registry_wide("registry.example.com", {"images": ["a:1"]})
            is False
        )
        assert engine.is_registry_wide("registry.example.com/team/app:1", {}) is False

    def test_cluster(self, tmp_path):
        provider = _provider(
            uid="prod",
            secret={"kubeconfig_content": "apiVersion: v1"},
            kind="kubernetes",
        )
        (unit,) = engine.prepare_units(
            mode="k8s",
            config={"namespace": "shop"},
            provider=provider,
            work_dir=tmp_path,
            limits=LIMITS,
        )
        assert unit.subcommand == "kubernetes" and unit.target_arg is None
        assert Path(unit.env["KUBECONFIG"]).is_file()
        assert unit.option_overrides == {"include_namespaces": ["shop"]}


def _target(mode="repo", config=None, application=None):
    return SimpleNamespace(mode=mode, config=config or {}, application=application)


class TestResolveOptions:
    def test_default_profile(self):
        ref, options = engine.resolve_options(tenant_id="t", target=_target())
        assert ref == "builtin:balanced"
        assert options["scanners"] == ["vuln", "misconfig", "secret"]

    def test_profile_precedence(self):
        application = SimpleNamespace(default_profile_ref="builtin:secrets")
        settings_row = SimpleNamespace(default_profiles={"repo": "builtin:iac"})
        ref, _ = engine.resolve_options(
            tenant_id="t", target=_target(), settings_row=settings_row
        )
        assert ref == "builtin:iac"
        ref, options = engine.resolve_options(
            tenant_id="t",
            target=_target(application=application),
            settings_row=settings_row,
        )
        assert ref == "builtin:secrets" and options["scanners"] == ["secret"]
        ref, _ = engine.resolve_options(
            tenant_id="t",
            target=_target(config={"profile": "builtin:full"}, application=application),
        )
        assert ref == "builtin:full"

    def test_profile_is_cut_to_what_the_target_supports(self):
        _, options = engine.resolve_options(
            tenant_id="t", target=_target("sbom", {"profile": "builtin:full"})
        )
        assert options["scanners"] == ["vuln", "license"]
        _, options = engine.resolve_options(
            tenant_id="t", target=_target("k8s", {"profile": "builtin:full"})
        )
        assert options["scanners"] == ["vuln", "misconfig", "secret", "rbac"]

    def test_targets_saved_before_profiles_keep_their_scanners(self):
        _, options = engine.resolve_options(
            tenant_id="t",
            target=_target(
                config={"scanners": ["vuln", "license"], "severity": "HIGH,CRITICAL"}
            ),
        )
        assert options["scanners"] == ["vuln", "license"]
        assert options["severities"] == ["HIGH", "CRITICAL"]

    def test_target_options_override_the_profile(self):
        _, options = engine.resolve_options(
            tenant_id="t",
            target=_target(
                config={
                    "profile": "builtin:release_gate",
                    "scanners": ["vuln", "misconfig", "secret"],
                    "options": {"ignore_unfixed": False, "skip_dirs": ["vendor"]},
                }
            ),
        )
        assert options["scanners"] == ["vuln", "secret"]  # the profile's, not legacy
        assert options["ignore_unfixed"] is False
        assert options["skip_dirs"] == ["vendor"]

    def test_unknown_profiles(self):
        with pytest.raises(OptionError, match="Unknown scan profile"):
            engine.profile_options("t", "builtin:nope")
        with pytest.raises(OptionError, match="Unknown scan profile"):
            engine.profile_options("t", "not-a-uuid")


class TestTargetConfigValidation:
    def test_root_filesystem_needs_an_archive(self):
        with pytest.raises(TrivyHubError, match="archive_b64 is required for rootfs"):
            validate_target_config("rootfs", {})
        cfg = validate_target_config("rootfs", {"archive_b64": _zip({"a": b"x"})})
        assert cfg["scanners"] == ["vuln", "misconfig", "secret", "license"]

    def test_profile_reference(self):
        base = {"repository_url": "https://git.example.com/acme/shop"}
        assert (
            validate_target_config("repo", {**base, "profile": "builtin:full"})[
                "profile"
            ]
            == "builtin:full"
        )
        assert "profile" not in validate_target_config("repo", {**base, "profile": ""})
        with pytest.raises(TrivyHubError, match="Unknown scan profile"):
            validate_target_config("repo", {**base, "profile": "builtin:nope"})
        with pytest.raises(TrivyHubError, match="not a profile id"):
            validate_target_config("repo", {**base, "profile": "abc"})
        validate_target_config(
            "repo", {**base, "profile": "0b0e6a8e-0a57-4c8e-9f0b-6f0f7b2f3c11"}
        )

    def test_options(self):
        base = {"repository_url": "https://git.example.com/acme/shop"}
        cfg = validate_target_config(
            "repo", {**base, "options": {"skip_dirs": ["vendor"], "branch": "main"}}
        )
        assert cfg["options"] == {"skip_dirs": ["vendor"], "branch": "main"}
        with pytest.raises(TrivyHubError, match="does not support platform"):
            validate_target_config(
                "repo", {**base, "options": {"platform": "linux/amd64"}}
            )
        with pytest.raises(TrivyHubError, match="Unknown scan option"):
            validate_target_config("repo", {**base, "options": {"shell": "rm -rf /"}})
        with pytest.raises(TrivyHubError, match="takes no scan options"):
            validate_target_config("sast", {**base, "options": {"skip_dirs": ["a"]}})


class TestLifecycleRules:
    def test_states(self):
        assert lifecycle.next_state(None) == "new"
        assert lifecycle.next_state("new") == "open"
        assert lifecycle.next_state("open") == "open"
        assert lifecycle.next_state("reopened") == "open"
        assert lifecycle.next_state("fixed") == "reopened"

    def test_uid_assignment(self):
        assert (
            lifecycle.assign_uid("trivy-repo-CVE-1-a-lock", "f" * 64, set())
            == "trivy-repo-CVE-1-a-lock"
        )
        taken = {"trivy-repo-CVE-1-a-lock"}
        suffixed = lifecycle.assign_uid("trivy-repo-CVE-1-a-lock", "abc123" * 11, taken)
        assert suffixed == "trivy-repo-CVE-1-a-lock-abc123abc123"
        assert len(lifecycle.assign_uid("x" * 300, "f" * 64, {"x" * 300})) <= 300
        assert lifecycle.assign_uid("", "f" * 64, set()).startswith("appsec-")

    def test_absence_is_evidence_only_when_the_scan_could_have_seen_it(self):
        full = lifecycle.coverage_for({"scanners": ["vuln", "secret"]})
        assert full.establishes_absence("vulnerability", "low", False)
        assert full.establishes_absence("secret", "high", None)
        # The scanner for the category did not run.
        assert not full.establishes_absence("license", "high", None)
        assert not full.establishes_absence("misconfiguration", "high", None)
        # Severity filter.
        gated = lifecycle.coverage_for(
            {"scanners": ["vuln"], "severities": ["HIGH", "CRITICAL"]}
        )
        assert gated.establishes_absence("vulnerability", "critical", True)
        assert not gated.establishes_absence("vulnerability", "medium", True)
        # Fixed-only filter hides unfixed vulnerabilities.
        fixed_only = lifecycle.coverage_for(
            {"scanners": ["vuln"], "ignore_unfixed": True}
        )
        assert fixed_only.establishes_absence("vulnerability", "high", True)
        assert not fixed_only.establishes_absence("vulnerability", "high", False)
        # Narrowed or partial scans never close findings.
        narrowed = lifecycle.coverage_for(
            {"scanners": ["vuln"], "skip_dirs": ["vendor"]}
        )
        assert not narrowed.complete and "skip_dirs" in narrowed.reasons[0]
        assert not narrowed.establishes_absence("vulnerability", "high", True)
        partial = lifecycle.coverage_for(
            {"scanners": ["vuln"]}, complete=False, reasons=["image b failed"]
        )
        assert not partial.establishes_absence("vulnerability", "high", True)
        assert partial.to_dict()["reasons"] == ["image b failed"]

    def test_rbac_and_sast_categories(self):
        assert lifecycle.coverage_for({"scanners": ["rbac"]}).categories == {
            "misconfiguration"
        }
        assert lifecycle.coverage_for({"scanners": ["sast"]}).categories == {"code"}


def _finding(**kwargs) -> NormalizedFinding:
    defaults = {
        "category": "vulnerability",
        "title": "t",
        "severity": "high",
        "rule_id": "CVE-1",
        "pkg_name": "lodash",
        "pkg_version": "1.0",
        "location": "package-lock.json",
        "fingerprint": "f1",
    }
    defaults.update(kwargs)
    return NormalizedFinding(**defaults)


class TestSharedRows:
    def test_vulnerability_row_keeps_the_shared_contract(self):
        finding = _finding(
            fixed_version="1.2",
            description="d",
            primary_url="https://u",
            ecosystem="npm",
            finding_type="lang-pkgs",
            raw={"PkgName": "lodash"},
        )
        row = shared_row(finding, "uid-1", mode="repo")
        assert row["uid"] == "uid-1" and row["status"] == "FAIL"
        assert row["check_id"] == "CVE-1" and row["severity"] == "high"
        assert row["resource_uid"] == "package-lock.json:lodash"
        assert row["check_metadata"]["Provider"] == "trivy"
        assert row["check_metadata"]["Remediation"]["Recommendation"]["Text"] == (
            "Upgrade lodash from 1.0 to 1.2 or later."
        )
        assert row["raw_result"] == {"PkgName": "lodash"}

    def test_unknown_severity_maps_to_low_only_in_the_shared_row(self):
        row = shared_row(_finding(severity="unknown"), "u", mode="repo")
        assert row["severity"] == "low"

    def test_remediation_by_category(self):
        assert "No fixed version" in remediation_text(
            _finding(details={"status": "affected"})
        )
        assert "rotate" in remediation_text(_finding(category="secret"))
        misconfig = _finding(
            category="misconfiguration", details={"resolution": "Enable encryption"}
        )
        assert remediation_text(misconfig) == "Enable encryption"
        text = remediation_text(
            _finding(
                category="license",
                rule_id="GPL-3.0",
                details={"license_category": "restricted"},
            )
        )
        assert "GPL-3.0" in text and "restricted" in text

    def test_secret_row_shows_only_the_masked_match(self):
        finding = parse_report(REPORT, mode="repo").findings[0]
        row = shared_row(finding, "u", mode="repo")
        assert "plaintext-leak" not in json.dumps(row)
        assert row["resource_services"] == ["secret"]


class TestInventory:
    def test_component_rows_count_vulnerabilities(self):
        components = [
            NormalizedComponent(
                name="lodash",
                version="1.0",
                ref="lodash@1.0",
                location="package-lock.json",
            ),
            NormalizedComponent(
                name="lodash",
                version="1.0",
                ref="lodash@1.0",
                location="package-lock.json",
            ),
            NormalizedComponent(
                name="axios",
                version="2.0",
                ref="axios@2.0",
                location="package-lock.json",
            ),
        ]
        findings = [
            _finding(fixed_version="1.2", details={"pkg_id": "lodash@1.0"}),
            _finding(
                rule_id="CVE-2",
                severity="critical",
                fixed_version="1.10",
                fingerprint="f2",
                details={"pkg_id": "lodash@1.0"},
            ),
            _finding(
                rule_id="CVE-3",
                suppressed=True,
                fingerprint="f3",
                details={"pkg_id": "axios@2.0"},
            ),
        ]
        lodash, axios = inventory.component_rows(components, findings)
        assert (
            lodash["vulnerability_count"] == 2 and lodash["max_severity"] == "critical"
        )
        assert lodash["fixed_version"] == "1.10"
        assert axios["vulnerability_count"] == 0 and axios["max_severity"] == ""

    def test_highest_fix(self):
        assert inventory.highest_fix(["1.2.3", "1.10.0", "1.9.9"]) == "1.10.0"
        assert inventory.highest_fix(["2.0.1, 3.0.0"]) == "2.0.1"
        assert inventory.highest_fix(["1.0.0-rc1", "1.0.0"]) in ("1.0.0-rc1", "1.0.0")
        assert inventory.highest_fix([]) == ""


class TestExports:
    def test_cluster_reports_cannot_be_converted(self):
        with pytest.raises(engine.EngineError, match="only be exported as JSON"):
            engine.convert_report({"ClusterName": "c", "Resources": []}, "sarif")
        with pytest.raises(engine.EngineError, match="Unknown format"):
            engine.convert_report({}, "pdf")

    def test_load_report_stays_inside_the_artifact_root(self, tmp_path, monkeypatch):
        monkeypatch.setattr(engine, "artifact_root", lambda: tmp_path)
        directory = engine.run_artifact_dir("tenant", "run")
        name = engine.store_report(directory, 0, {"Results": []})
        run = SimpleNamespace(artifact_path="tenant/run")
        assert engine.load_report(run) == {"Results": []}
        assert name == "report-0.json.gz"
        assert engine.load_report(SimpleNamespace(artifact_path="")) is None
        assert engine.load_report(SimpleNamespace(artifact_path="../../etc")) is None
        assert engine.load_report(SimpleNamespace(artifact_path="tenant/other")) is None


class TestRateLimitClassification:
    def test_registry_429_is_rate_limited(self):
        result = failures.classify_failure(
            1,
            "FATAL Error remote Maven repository returned 429 Too Many Requests",
        )
        assert result.kind == failures.FAILURE_RATE_LIMITED
        assert result.message.startswith("A package registry rate-limited")

    def test_database_download_limit_stays_a_database_failure(self):
        result = failures.classify_failure(
            1, "FATAL failed to download vulnerability DB: TOOMANYREQUESTS"
        )
        assert result.kind == failures.FAILURE_DATABASE and result.retryable
