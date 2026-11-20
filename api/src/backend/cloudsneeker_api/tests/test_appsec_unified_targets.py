"""One target per repository: static analysis in the repository run and
extra branches on the same target.

No database: services are exercised with plain values and fakes.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cloudsneeker_api.appsec import engine, lifecycle, parser, queries
from cloudsneeker_api.services import branch_policy
from cloudsneeker_api.services.repo_branches import parse_remote_refs
from cloudsneeker_api.services.sast import normalize_repo_sast, repo_sast_config
from cloudsneeker_api.services.trivy import TrivyHubError, validate_target_config

REPO_URL = "https://github.com/acme/shop"


class TestRepoSastConfig:
    def test_true_enables_automatic_rules(self):
        assert normalize_repo_sast(True) == {"rulesets": ["auto"], "exclude": []}

    @pytest.mark.parametrize("value", [None, False, {}, {"enabled": False}])
    def test_off_values(self, value):
        assert normalize_repo_sast(value) is None

    def test_rulesets_and_exclude_are_validated(self):
        assert normalize_repo_sast(
            {"rulesets": ["python"], "exclude": ["tests/**"]}
        ) == {"rulesets": ["python"], "exclude": ["tests/**"]}
        with pytest.raises(TrivyHubError):
            normalize_repo_sast({"rulesets": ["nope"]})
        with pytest.raises(TrivyHubError):
            normalize_repo_sast("yes")

    def test_repository_target_keeps_sast(self):
        cfg = validate_target_config("repo", {"repository_url": REPO_URL, "sast": True})
        assert cfg["sast"] == {"rulesets": ["auto"], "exclude": []}
        assert "sast" not in validate_target_config(
            "repo", {"repository_url": REPO_URL, "sast": False}
        )

    def test_other_modes_refuse_sast(self):
        with pytest.raises(TrivyHubError, match="code repository"):
            validate_target_config("sbom", {"sbom": "{}", "sast": True})

    def test_repo_sast_config_follows_the_target(self):
        cfg = validate_target_config(
            "repo",
            {
                "repository_url": REPO_URL,
                "branch": "develop",
                "sast": {"rulesets": ["javascript"]},
            },
        )
        assert repo_sast_config(cfg) == {
            "repository_url": REPO_URL,
            "rulesets": ["javascript"],
            "exclude": [],
            "branch": "develop",
        }
        assert repo_sast_config({"repository_url": REPO_URL}) is None


class TestBranchPatterns:
    def test_names_and_patterns(self):
        assert branch_policy.normalize_branch_patterns(
            ["main", " release/* ", "main", "", "hotfix-?"]
        ) == ["main", "release/*", "hotfix-?"]
        assert branch_policy.normalize_branch_patterns("a, b\nc") == ["a", "b", "c"]
        assert branch_policy.normalize_branch_patterns(None) == []

    @pytest.mark.parametrize("value", ["-x", "a..b", "a b", "--upload-pack=x", "../*"])
    def test_unsafe_values(self, value):
        with pytest.raises(branch_policy.BranchPolicyError):
            branch_policy.normalize_branch_patterns([value])

    def test_limit(self):
        with pytest.raises(branch_policy.BranchPolicyError):
            branch_policy.normalize_branch_patterns(
                [f"b{i}" for i in range(branch_policy.MAX_PATTERNS + 1)]
            )

    def test_target_config(self):
        cfg = validate_target_config(
            "repo", {"repository_url": REPO_URL, "branches": ["release/*"]}
        )
        assert cfg["branches"] == ["release/*"]
        with pytest.raises(TrivyHubError, match="repository URL"):
            validate_target_config("sbom", {"sbom": "{}", "branches": ["x"]})
        with pytest.raises(TrivyHubError):
            validate_target_config(
                "repo", {"repository_url": REPO_URL, "branches": ["a..b"]}
            )

    def test_matching_keeps_listing_order_and_skips_main(self):
        branches = ["main", "develop", "release/1", "release/2", "feature/x"]
        assert branch_policy.matching_branches(
            ["release/*", "develop", "main"], branches, exclude={"main"}
        ) == ["develop", "release/1", "release/2"]
        assert branch_policy.matching_branches([], branches) == []


class TestPlanBranchRuns:
    def test_unchanged_branches_are_skipped(self):
        runs, skipped = branch_policy.plan_branch_runs(
            ["a", "b", "c"],
            {"a": "1", "b": "2", "c": "3"},
            {"a": "1", "b": "old"},
            limit=10,
        )
        assert [run.branch for run in runs] == ["b", "c"]
        assert runs[0].commit == "2"
        assert skipped == ["a"]

    def test_force_and_limit(self):
        runs, skipped = branch_policy.plan_branch_runs(
            ["a", "b", "c"], {"a": "1"}, {"a": "1"}, limit=2, force=True
        )
        assert [run.branch for run in runs] == ["a", "b"]
        assert skipped == []

    def test_unknown_commit_is_always_scanned(self):
        runs, _ = branch_policy.plan_branch_runs(["a"], {}, {"a": ""}, limit=5)
        assert [run.branch for run in runs] == ["a"]

    def test_cap_from_environment(self, monkeypatch):
        monkeypatch.setenv("APPSEC_MAX_BRANCHES_PER_SCAN", "7")
        assert branch_policy.max_branches_per_scan() == 7
        monkeypatch.setenv("APPSEC_MAX_BRANCHES_PER_SCAN", "x")
        assert branch_policy.max_branches_per_scan() == 20


def test_listing_returns_head_commits():
    listing = parse_remote_refs(
        {b"refs/heads/main": b"aaa", b"refs/heads/dev": b"bbb", b"refs/tags/v1": b"c"}
    )
    assert listing.commits == {"dev": "bbb", "main": "aaa"}


class TestCombinedCoverage:
    def test_each_part_answers_for_its_categories(self):
        dependencies = lifecycle.coverage_for({"scanners": ["vuln", "secret"]})
        code = lifecycle.Coverage(complete=False, reasons=["Static analysis: x"])
        combined = lifecycle.combine_coverage(dependencies, code)
        assert combined.establishes_absence(parser.CATEGORY_VULNERABILITY, "high", True)
        assert combined.establishes_absence(parser.CATEGORY_SECRET, "high", None)
        # The failed step proves nothing about code findings.
        assert not combined.establishes_absence(parser.CATEGORY_CODE, "high", None)

    def test_failed_dependency_scan_does_not_block_code(self):
        dependencies = lifecycle.coverage_for(
            {"scanners": ["vuln"]}, complete=False, reasons=["unit failed"]
        )
        code = lifecycle.coverage_for({"scanners": ["sast"]}, unknown_paths=["a.py"])
        combined = lifecycle.combine_coverage(dependencies, code)
        assert not combined.establishes_absence(
            parser.CATEGORY_VULNERABILITY, "high", True
        )
        assert combined.establishes_absence(parser.CATEGORY_CODE, "low", None, "b.py")
        assert not combined.establishes_absence(
            parser.CATEGORY_CODE, "low", None, "a.py"
        )

    def test_to_dict_merges_parts(self):
        combined = lifecycle.combine_coverage(
            lifecycle.coverage_for({"scanners": ["vuln"], "severities": ["HIGH"]}),
            lifecycle.coverage_for(
                {"scanners": ["sast"]}, complete=False, reasons=["r"]
            ),
        )
        data = combined.to_dict()
        assert data["categories"] == sorted(
            [parser.CATEGORY_VULNERABILITY, parser.CATEGORY_CODE]
        )
        assert data["severities"] is None
        assert data["complete"] is False
        assert data["reasons"] == ["r"]
        assert len(data["parts"]) == 2

    def test_single_part_is_returned_as_is(self):
        coverage = lifecycle.coverage_for({"scanners": ["vuln"]})
        assert lifecycle.combine_coverage(coverage) is coverage


class TestEngineCodeStep:
    def test_run_branch_overrides_git_targets_only(self):
        cfg = {"repository_url": REPO_URL, "branch": "main"}
        assert engine.apply_run_branch(cfg, "dev")["branch"] == "dev"
        assert engine.apply_run_branch(cfg, "") is cfg
        assert engine.apply_run_branch({"sbom": "{}"}, "dev") == {"sbom": "{}"}

    def test_summary_keeps_the_queued_commit(self):
        assert engine.run_summary_base(SimpleNamespace(summary={"commit": "abc"})) == {
            "commit": "abc"
        }
        assert engine.run_summary_base(SimpleNamespace(summary={})) == {}

    def test_no_step_without_sast(self):
        assert (
            engine.run_code_step({"repository_url": REPO_URL}, None, [], lambda: False)
            is None
        )

    def test_step_is_skipped_when_every_unit_failed_or_cancelled(self):
        cfg = {"repository_url": REPO_URL, "sast": {"rulesets": ["auto"]}}
        failed = [SimpleNamespace(parsed=None)]
        assert engine.run_code_step(cfg, None, failed, lambda: False) is None
        ok = [SimpleNamespace(parsed=object())]
        assert engine.run_code_step(cfg, None, ok, lambda: True) is None

    def test_step_failure_is_recorded_not_raised(self):
        cfg = {"repository_url": REPO_URL, "sast": {"rulesets": ["auto"]}}
        ok = [SimpleNamespace(parsed=object())]
        with patch(
            "cloudsneeker_api.services.sast.run_opengrep_scan",
            side_effect=TrivyHubError("clone failed"),
        ):
            step = engine.run_code_step(cfg, None, ok, lambda: False)
        assert step.report is None and "clone failed" in step.error
        assert step.summary(3)["status"] == "failed"
        assert step.summary(3)["finding_count"] == 0
        findings, rows_for, coverage = engine._code_step_results(step)
        assert findings == [] and rows_for is None
        assert not coverage.establishes_absence(parser.CATEGORY_CODE, "high", None)

    def test_step_results_build_findings_and_rows(self):
        report = {
            "results": [
                {
                    "check_id": "python.lang.security.eval",
                    "path": "app.py",
                    "start": {"line": 3},
                    "end": {"line": 3},
                    "extra": {"severity": "ERROR", "message": "eval"},
                }
            ],
            "errors": [],
        }
        step = engine.CodeStep(
            config={"rulesets": ["auto"], "exclude": []}, report=report
        )
        findings, rows_for, coverage = engine._code_step_results(step)
        assert len(findings) == 1
        assert findings[0].category == parser.CATEGORY_CODE
        rows = rows_for({findings[0].fingerprint: "uid-1"})
        assert [row["uid"] for row in rows] == ["uid-1"]
        assert coverage.establishes_absence(parser.CATEGORY_CODE, "high", None)
        assert step.summary(1) == {
            "status": "completed",
            "finding_count": 1,
            "duration_ms": 0,
        }


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, ""), ("", ""), ("dev", "dev"), ("*", None), (" release/1 ", "release/1")],
)
def test_branch_param(value, expected):
    params = {} if value is None else {"filter[branch]": value}
    assert queries.branch_param(params) == expected
