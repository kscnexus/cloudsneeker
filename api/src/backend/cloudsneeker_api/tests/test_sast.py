"""Static analysis (SAST) mode: config, rules, command, clone, run, and import."""

from __future__ import annotations

import base64
import io
import json
import subprocess
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cloudsneeker_api.models import TrivyTarget
from cloudsneeker_api.services import sast
from cloudsneeker_api.services.sast import (
    SAST_RULESETS,
    build_opengrep_command,
    clone_repository,
    detect_rulesets,
    normalize_report,
    resolve_opengrep_bin,
    resolve_rule_dirs,
    run_opengrep_scan,
    validate_sast_config,
)
from cloudsneeker_api.services.trivy import (
    MODE_PROVIDER_TYPES,
    TRIVY_MODES,
    TrivyHubError,
    assert_provider_matches_mode,
    is_valid_trivy_mode,
    process_trivy_run,
    validate_target_config,
)
from cloudsneeker_api.services.trivy_import import (
    bounded_uid,
    compact_report_output,
    normalize_rule_id,
    opengrep_results_to_finding_rows,
    opengrep_severity,
    report_to_finding_rows,
)

REPO_URL = "https://bitbucket.org/acme/app.git"
TOKEN = "sast-secret-token"
AUTH_URL = f"https://x-token-auth:{TOKEN}@bitbucket.org/acme/app.git"


def _iac_provider(secret: dict | None = None, uid: str = REPO_URL) -> MagicMock:
    provider = MagicMock()
    provider.provider = "iac"
    provider.uid = uid
    provider.secret.secret = secret or {}
    return provider


def _zip_b64(files: dict[str, str]) -> str:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return base64.b64encode(buffer.getvalue()).decode()


def _rules_root(tmp_path: Path, *folders: str) -> Path:
    root = tmp_path / "rules"
    for folder in folders:
        (root / folder).mkdir(parents=True)
        (root / folder / "rule.yml").write_text("rules: []\n", encoding="utf-8")
    return root


def _result(**overrides) -> dict:
    result = {
        "check_id": "opt.opengrep.rules.python.eval.python_eval_rule-eval",
        "path": "app/views.py",
        "start": {"line": 10, "col": 5},
        "end": {"line": 12, "col": 1},
        "extra": {
            "message": "Use of eval detected.",
            "severity": "ERROR",
            "metadata": {
                "cwe": "CWE-95",
                "owasp": ["A03:2021-Injection"],
                "shortDescription": "Eval injection",
                "references": ["https://cwe.mitre.org/data/definitions/95.html"],
            },
            "lines": "eval(user_input)",
        },
    }
    result.update(overrides)
    return result


class TestSastMode:
    def test_mode_is_registered(self):
        assert TrivyTarget.Mode.SAST == "sast"
        assert "sast" in TRIVY_MODES
        assert is_valid_trivy_mode("sast")
        assert MODE_PROVIDER_TYPES["sast"] == {"iac"}

    def test_model_choice_label(self):
        assert dict(TrivyTarget.Mode.choices)["sast"] == "Static analysis (SAST)"


class TestValidateSastConfig:
    def test_requires_repository_or_archive(self):
        with pytest.raises(TrivyHubError, match="repository_url or config.archive_b64"):
            validate_target_config("sast", {})

    def test_rejects_both_sources(self):
        with pytest.raises(TrivyHubError, match="not both"):
            validate_target_config(
                "sast", {"repository_url": REPO_URL, "archive_b64": "UEsDBA=="}
            )

    def test_rejects_worker_path(self):
        with pytest.raises(TrivyHubError, match="config.path is not supported"):
            validate_target_config("sast", {"path": "/etc", "repository_url": REPO_URL})

    def test_rejects_embedded_credentials(self):
        with pytest.raises(TrivyHubError, match="must not contain credentials"):
            validate_target_config("sast", {"repository_url": AUTH_URL})

    def test_repository_defaults(self):
        cfg = validate_target_config(
            "sast", {"url": f" {REPO_URL} ", "scanners": ["vuln"], "severity": "HIGH"}
        )
        assert cfg == {"repository_url": REPO_URL, "rulesets": ["auto"], "exclude": []}

    def test_archive_source(self):
        cfg = validate_target_config("sast", {"archive_b64": "UEsDBA==", "path": ""})
        assert cfg["archive_b64"] == "UEsDBA=="
        assert "repository_url" not in cfg
        assert "path" not in cfg

    def test_archive_size_limit(self):
        with patch.object(sast, "MAX_ARCHIVE_BYTES", 2):
            with pytest.raises(TrivyHubError, match="size limit"):
                validate_sast_config({"archive_b64": "A" * 10})

    def test_rulesets_are_normalized(self):
        cfg = validate_sast_config(
            {"repository_url": REPO_URL, "rulesets": ["Python", "go", "python"]}
        )
        assert cfg["rulesets"] == ["python", "go"]

    def test_ruleset_string_is_accepted(self):
        cfg = validate_sast_config({"repository_url": REPO_URL, "rulesets": "all"})
        assert cfg["rulesets"] == ["all"]

    def test_unknown_ruleset(self):
        with pytest.raises(TrivyHubError, match="Unknown ruleset 'p/default'"):
            validate_sast_config({"repository_url": REPO_URL, "rulesets": ["p/default"]})

    def test_rulesets_must_be_strings(self):
        with pytest.raises(TrivyHubError, match="list of ruleset names"):
            validate_sast_config({"repository_url": REPO_URL, "rulesets": [1]})

    def test_auto_cannot_be_combined(self):
        with pytest.raises(TrivyHubError, match="cannot be combined"):
            validate_sast_config(
                {"repository_url": REPO_URL, "rulesets": ["auto", "python"]}
            )

    def test_exclude_is_normalized(self):
        cfg = validate_sast_config(
            {"repository_url": REPO_URL, "exclude": [" tests/** ", "*.min.js"]}
        )
        assert cfg["exclude"] == ["tests/**", "*.min.js"]
        cfg = validate_sast_config({"repository_url": REPO_URL, "exclude": "docs"})
        assert cfg["exclude"] == ["docs"]

    @pytest.mark.parametrize(
        ("exclude", "match"),
        [
            ({"a": 1}, "list of glob patterns"),
            ([""], "list of glob patterns"),
            ([3], "list of glob patterns"),
            (["x" * 201], "too long or invalid"),
            (["a\x00b"], "too long or invalid"),
            (["*"] * 51, "at most 50"),
        ],
    )
    def test_exclude_rejects_bad_values(self, exclude, match):
        with pytest.raises(TrivyHubError, match=match):
            validate_sast_config({"repository_url": REPO_URL, "exclude": exclude})


class TestSastProviderCheck:
    def test_rejects_cloud_account(self):
        provider = MagicMock()
        provider.provider = "aws"
        with pytest.raises(TrivyHubError, match="requires provider type"):
            assert_provider_matches_mode(provider, "sast", {"archive_b64": "x"})

    def test_repository_must_match_provider(self):
        with pytest.raises(TrivyHubError, match="must match the linked IaC provider"):
            assert_provider_matches_mode(
                _iac_provider(),
                "sast",
                {"repository_url": "https://evil.example/acme/app"},
            )

    def test_matching_repository_and_archive_pass(self):
        provider = _iac_provider(uid="https://bitbucket.org/acme/app")
        assert_provider_matches_mode(provider, "sast", {"repository_url": REPO_URL})
        assert_provider_matches_mode(provider, "sast", {"archive_b64": "x"})


class TestRuleSelection:
    def test_detects_languages_and_skips_vendor_dirs(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1", encoding="utf-8")
        (tmp_path / "web").mkdir()
        (tmp_path / "web" / "index.TSX").write_text("", encoding="utf-8")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "lib.go").write_text("", encoding="utf-8")
        assert detect_rulesets(tmp_path) == ["python", "typescript"]

    def test_detection_stops_at_file_cap(self, tmp_path):
        for index in range(3):
            (tmp_path / f"f{index}.py").write_text("", encoding="utf-8")
        with patch.object(sast, "MAX_DETECT_FILES", 1):
            assert detect_rulesets(tmp_path) == ["python"]

    def test_auto_uses_detected_packs(self, tmp_path):
        root = _rules_root(tmp_path, "python", "javascript", "go")
        src = tmp_path / "src"
        src.mkdir()
        (src / "a.ts").write_text("", encoding="utf-8")
        (src / "b.js").write_text("", encoding="utf-8")
        assert resolve_rule_dirs(["auto"], src, root) == [root / "javascript"]

    def test_auto_falls_back_to_all(self, tmp_path):
        root = _rules_root(tmp_path, "python", "go")
        src = tmp_path / "src"
        src.mkdir()
        assert resolve_rule_dirs([], src, root) == [root / "go", root / "python"]

    def test_explicit_and_missing_packs(self, tmp_path):
        root = _rules_root(tmp_path, "java")
        assert resolve_rule_dirs(["java", "scala", "bogus"], tmp_path, root) == [
            root / "java"
        ]
        with pytest.raises(TrivyHubError, match="No static analysis rules"):
            resolve_rule_dirs(["python"], tmp_path, root)

    def test_rules_root_from_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("OPENGREP_RULES_DIR", str(tmp_path))
        assert sast.rules_root() == tmp_path
        monkeypatch.setenv("OPENGREP_RULES_DIR", "")
        assert sast.rules_root() == Path("/opt/opengrep/rules")

    def test_allowlist_has_no_registry_packs(self):
        assert all("/" not in folder for folder in SAST_RULESETS.values())


class TestOpengrepBinary:
    def test_env_wins(self, monkeypatch):
        monkeypatch.setenv("OPENGREP_BIN", "/opt/opengrep/opengrep")
        assert resolve_opengrep_bin() == "/opt/opengrep/opengrep"

    def test_path_lookup_and_missing(self, monkeypatch):
        monkeypatch.delenv("OPENGREP_BIN", raising=False)
        with patch("cloudsneeker_api.services.sast.shutil.which", return_value="/bin/og"):
            assert resolve_opengrep_bin() == "/bin/og"
        with patch("cloudsneeker_api.services.sast.shutil.which", return_value=None):
            with pytest.raises(TrivyHubError, match="engine was not found"):
                resolve_opengrep_bin()


class TestBuildOpengrepCommand:
    def test_rules_exclude_and_timeout(self):
        argv = build_opengrep_command(
            binary="opengrep",
            rule_dirs=[Path("/r/python"), Path("/r/go")],
            exclude=["tests/**", "*.min.js"],
            timeout_seconds=15,
            jobs="",
        )
        assert argv[:2] == ["opengrep", "scan"]
        assert "--json" in argv
        assert "--disable-version-check" in argv
        assert f"--config={Path('/r/python')}" in argv
        assert f"--config={Path('/r/go')}" in argv
        assert "--exclude=tests/**" in argv
        assert "--exclude=*.min.js" in argv
        assert "--timeout=15" in argv
        assert not any(arg.startswith("--metrics") for arg in argv)
        assert not any(arg.startswith("--jobs") for arg in argv)
        assert argv[-1] == "."

    def test_jobs_only_when_numeric(self):
        argv = build_opengrep_command(
            binary="og", rule_dirs=[Path("/r")], exclude=[], jobs="4"
        )
        assert "--jobs=4" in argv
        argv = build_opengrep_command(
            binary="og", rule_dirs=[Path("/r")], exclude=[], jobs="4; rm"
        )
        assert not any(arg.startswith("--jobs") for arg in argv)


class TestCloneRepository:
    def test_clones_with_token_and_removes_git_dir(self, tmp_path):
        def fake_clone(url, target, **kwargs):
            (Path(target) / ".git").mkdir(parents=True)
            (Path(target) / "app.py").write_text("", encoding="utf-8")

        provider = _iac_provider({"access_token": TOKEN})
        with patch("dulwich.porcelain.clone", side_effect=fake_clone) as mock_clone:
            secrets = clone_repository(REPO_URL, provider, tmp_path)
        assert mock_clone.call_args.args[0] == AUTH_URL
        assert mock_clone.call_args.kwargs["depth"] == 1
        assert not (tmp_path / ".git").exists()
        assert (tmp_path / "app.py").exists()
        assert set(secrets) == {AUTH_URL, TOKEN}

    def test_public_repository_has_no_secrets(self, tmp_path):
        with patch("dulwich.porcelain.clone") as mock_clone:
            secrets = clone_repository(REPO_URL, _iac_provider(), tmp_path)
        assert mock_clone.call_args.args[0] == REPO_URL
        assert secrets == ()

    def test_clone_error_is_redacted(self, tmp_path):
        provider = _iac_provider({"access_token": TOKEN})
        with patch(
            "dulwich.porcelain.clone",
            side_effect=OSError(f"401 for {AUTH_URL} token={TOKEN}"),
        ):
            with pytest.raises(TrivyHubError) as exc_info:
                clone_repository(REPO_URL, provider, tmp_path)
        assert TOKEN not in str(exc_info.value)
        assert "Repository clone failed" in str(exc_info.value)


class TestNormalizeReport:
    def test_paths_become_relative(self, tmp_path):
        report = {
            "results": [
                {"path": f"{tmp_path}/app/a.py"},
                {"path": "./b.py"},
                "junk",
            ],
            "errors": [{"path": f"{tmp_path}\\c.py"}],
        }
        normalize_report(report, tmp_path)
        assert report["results"][0]["path"] == "app/a.py"
        assert report["results"][1]["path"] == "b.py"
        assert report["errors"][0]["path"] == "c.py"

    def test_ignores_missing_lists(self, tmp_path):
        assert normalize_report({"results": None}, tmp_path) == {"results": None}


class TestRunOpengrepScan:
    @pytest.fixture(autouse=True)
    def _engine(self, tmp_path, monkeypatch):
        monkeypatch.setenv(
            "OPENGREP_RULES_DIR", str(_rules_root(tmp_path, "python", "go"))
        )
        with patch(
            "cloudsneeker_api.services.sast.resolve_opengrep_bin",
            return_value="opengrep",
        ):
            yield

    def test_archive_scan_runs_in_source_tree(self):
        captured: dict = {}

        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return MagicMock(
                stdout=json.dumps(
                    {"results": [{"path": f"{kwargs['cwd']}/app.py"}], "errors": []}
                ),
                stderr="",
                returncode=1,
            )

        config = validate_sast_config(
            {"archive_b64": _zip_b64({"app.py": "eval(x)"}), "exclude": ["tests"]}
        )
        with patch("cloudsneeker_api.services.sast.subprocess.run", side_effect=fake_run):
            report = run_opengrep_scan(config=config, provider=_iac_provider())
        assert report["results"][0]["path"] == "app.py"
        assert report["cloudsneeker_rulesets"] == ["python"]
        assert "--exclude=tests" in captured["argv"]
        assert captured["argv"][-1] == "."
        assert captured["kwargs"]["timeout"] >= sast.MIN_SCAN_SECONDS
        assert not Path(captured["kwargs"]["cwd"]).exists()

    def _run_repo(self, process=None, side_effect=None):
        def fake_clone(url, target, **kwargs):
            (Path(target) / "main.go").write_text("", encoding="utf-8")

        provider = _iac_provider({"access_token": TOKEN})
        config = validate_sast_config({"repository_url": REPO_URL})
        with (
            patch("dulwich.porcelain.clone", side_effect=fake_clone),
            patch(
                "cloudsneeker_api.services.sast.subprocess.run",
                return_value=process,
                side_effect=side_effect,
            ),
        ):
            return run_opengrep_scan(config=config, provider=provider)

    def test_repository_report_is_scrubbed(self):
        process = MagicMock(
            stdout=json.dumps({"results": [], "errors": [{"message": AUTH_URL}]}),
            stderr="",
            returncode=0,
        )
        report = self._run_repo(process)
        assert TOKEN not in json.dumps(report)
        assert report["cloudsneeker_rulesets"] == ["go"]

    def test_stderr_error_is_redacted(self):
        process = MagicMock(stdout="", stderr=f"fatal: {AUTH_URL}", returncode=2)
        with pytest.raises(TrivyHubError) as exc_info:
            self._run_repo(process)
        assert TOKEN not in str(exc_info.value)
        assert "fatal" in str(exc_info.value)

    def test_no_output(self):
        process = MagicMock(stdout=" ", stderr="", returncode=2)
        with pytest.raises(TrivyHubError, match="no output \\(exit 2\\)"):
            self._run_repo(process)

    def test_invalid_json(self):
        process = MagicMock(stdout="{nope", stderr="", returncode=2)
        with pytest.raises(TrivyHubError, match="invalid JSON"):
            self._run_repo(process)

    def test_json_root_must_be_object(self):
        process = MagicMock(stdout="[]", stderr="", returncode=0)
        with pytest.raises(TrivyHubError, match="root must be an object"):
            self._run_repo(process)

    def test_timeout_never_carries_argv(self):
        error = subprocess.TimeoutExpired(cmd=[AUTH_URL], timeout=1)
        with pytest.raises(TrivyHubError, match="timed out") as exc_info:
            self._run_repo(side_effect=error)
        assert TOKEN not in str(exc_info.value)

    def test_unexpected_error_is_redacted(self):
        with pytest.raises(TrivyHubError) as exc_info:
            self._run_repo(side_effect=OSError(f"exec failed {TOKEN}"))
        assert TOKEN not in str(exc_info.value)

    def test_unexpected_error_without_secrets_propagates(self):
        config = validate_sast_config({"archive_b64": _zip_b64({"a.py": ""})})
        with patch(
            "cloudsneeker_api.services.sast.subprocess.run",
            side_effect=OSError("exec failed"),
        ):
            with pytest.raises(OSError):
                run_opengrep_scan(config=config, provider=_iac_provider())


class TestOpengrepSeverity:
    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            ("ERROR", "high"),
            ("WARNING", "medium"),
            ("INFO", "low"),
            ("CRITICAL", "critical"),
            ("bogus", "medium"),
            (None, "medium"),
        ],
    )
    def test_rule_severity(self, severity, expected):
        assert opengrep_severity({"severity": severity}) == expected

    def test_security_severity_wins(self):
        extra = {"severity": "WARNING", "metadata": {"security-severity": "Critical"}}
        assert opengrep_severity(extra) == "critical"
        extra = {"severity": "ERROR", "metadata": {"security-severity": "Info"}}
        assert opengrep_severity(extra) == "informational"

    def test_high_impact_and_confidence_raise_to_critical(self):
        metadata = {"impact": "HIGH", "confidence": "high"}
        assert opengrep_severity({"severity": "ERROR", "metadata": metadata}) == (
            "critical"
        )
        assert opengrep_severity({"severity": "WARNING", "metadata": metadata}) == (
            "medium"
        )
        metadata = {"impact": "HIGH", "confidence": "LOW"}
        assert opengrep_severity({"severity": "ERROR", "metadata": metadata}) == "high"


class TestOpengrepMapping:
    def test_maps_result_to_finding_row(self):
        rows = opengrep_results_to_finding_rows({"results": [_result()]})
        assert len(rows) == 1
        row = rows[0]
        assert row["check_id"] == "python_eval_rule-eval"
        assert row["uid"] == "opengrep-sast-python_eval_rule-eval-app/views.py:10-12"
        assert row["status"] == "FAIL"
        assert row["severity"] == "high"
        assert row["status_extended"] == "app/views.py:10-12: Use of eval detected."
        assert row["resource_uid"] == "app/views.py"
        assert row["resource_services"] == ["sast"]
        assert row["resource_types"] == ["source-file"]
        metadata = row["check_metadata"]
        assert metadata["CheckTitle"] == "Eval injection"
        assert metadata["Description"] == "Use of eval detected."
        assert metadata["ServiceName"] == "sast"
        assert metadata["ResourceType"] == "source-file"
        assert metadata["Categories"] == ["CWE-95", "A03:2021-Injection"]
        assert "CWE-95" in metadata["Risk"]
        assert metadata["RelatedUrl"].startswith("https://cwe.mitre.org")
        assert metadata["Remediation"]["Recommendation"]["Text"].startswith("Review")

    def test_fix_and_risk_metadata(self):
        result = _result()
        result["extra"]["fix"] = "ast.literal_eval(user_input)"
        result["extra"]["metadata"].update({"impact": "HIGH", "likelihood": "LOW"})
        row = opengrep_results_to_finding_rows({"results": [result]})[0]
        remediation = row["check_metadata"]["Remediation"]
        assert remediation["Code"]["Other"] == "ast.literal_eval(user_input)"
        assert "ast.literal_eval" in remediation["Recommendation"]["Text"]
        assert "Impact: HIGH." in row["check_metadata"]["Risk"]
        assert "Likelihood: LOW." in row["check_metadata"]["Risk"]

    def test_minimal_and_malformed_results(self):
        report = {
            "results": [
                "junk",
                {"check_id": "custom.rule", "start": {"line": "x"}, "extra": None},
                _result(extra={"is_ignored": True}),
            ]
        }
        rows = opengrep_results_to_finding_rows(report)
        assert len(rows) == 1
        assert rows[0]["check_id"] == "custom.rule"
        assert rows[0]["severity"] == "medium"
        assert rows[0]["resource_uid"] == "source"
        assert rows[0]["check_metadata"]["Categories"] == []
        assert opengrep_results_to_finding_rows({"results": "bad"}) == []

    def test_long_lines_are_trimmed(self):
        result = _result()
        result["extra"]["lines"] = "x" * 5000
        row = opengrep_results_to_finding_rows({"results": [result]})[0]
        assert len(row["raw_result"]["extra"]["lines"]) == 2000

    def test_long_uids_stay_unique_and_bounded(self):
        base = "a/" * 200
        rows = opengrep_results_to_finding_rows(
            {"results": [_result(path=f"{base}one.py"), _result(path=f"{base}two.py")]}
        )
        assert all(len(row["uid"]) == 300 for row in rows)
        assert rows[0]["uid"] != rows[1]["uid"]
        assert len(rows[0]["resource_uid"]) == 300

    def test_bounded_uid_keeps_short_values(self):
        assert bounded_uid("short") == "short"

    def test_normalize_rule_id(self):
        assert normalize_rule_id(
            "tmp.rules.python.crypto.python_crypto_rule-crypto.hazmat-hash-md5"
        ) == "python_crypto_rule-crypto.hazmat-hash-md5"
        assert normalize_rule_id("my.custom.rule") == "my.custom.rule"

    def test_dispatch_by_mode(self):
        assert len(report_to_finding_rows({"results": [_result()]}, mode="sast")) == 1
        assert report_to_finding_rows({"results": [_result()]}, mode="fs") == []

    def test_compact_output(self):
        report = {
            "results": [_result(), _result(), _result(path="b.py"), "junk"],
            "errors": [{}],
            "cloudsneeker_rulesets": ["python"],
        }
        assert compact_report_output(report, mode="sast") == {
            "result_targets": ["app/views.py", "b.py"],
            "rulesets": ["python"],
            "error_count": 1,
        }
        assert compact_report_output({"Results": [{"Target": "t"}]}, mode="fs") == {
            "result_targets": ["t"]
        }


class TestProcessSastRun:
    def test_sast_run_uses_opengrep_and_imports(self):
        run = MagicMock()
        run.status = "pending"
        run.target.mode = "sast"
        run.target.name = "app"
        run.target.config = {"archive_b64": "UEsDBA=="}
        run.provider = _iac_provider()
        scan = MagicMock()
        scan.id = "scan-1"
        report = {"results": [_result()], "errors": [], "cloudsneeker_rulesets": ["go"]}

        mock_runs = MagicMock()
        mock_runs.select_related.return_value.filter.return_value.first.return_value = (
            run
        )
        rls = MagicMock()
        rls.return_value.__exit__.return_value = False
        with (
            patch("cloudsneeker_api.services.trivy.rls_transaction", rls),
            patch("cloudsneeker_api.services.trivy.TrivyRun.objects", mock_runs),
            patch(
                "cloudsneeker_api.services.sast.run_opengrep_scan",
                return_value=report,
            ) as mock_scan,
            patch("cloudsneeker_api.services.trivy.run_trivy_cli") as mock_trivy,
            patch(
                "cloudsneeker_api.services.trivy_import.import_trivy_report",
                return_value=scan,
            ) as mock_import,
        ):
            result = process_trivy_run(tenant_id="t-1", run_id="r-1")

        assert result == {"status": "completed", "run_id": "r-1", "scan_id": "scan-1"}
        mock_scan.assert_called_once()
        mock_trivy.assert_not_called()
        kwargs = mock_import.call_args.kwargs
        assert kwargs["mode"] == "sast"
        assert kwargs["scan_name"] == "SAST: app"
        assert len(kwargs["rows"]) == 1
        assert run.summary["finding_count"] == 1
        assert run.output["rulesets"] == ["go"]
