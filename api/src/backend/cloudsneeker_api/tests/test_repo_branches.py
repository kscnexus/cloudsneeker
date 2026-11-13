"""Branch listing and branch selection for repository and SAST targets."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cloudsneeker.git_ssh import GitSshError
from cloudsneeker_api.appsec import engine
from cloudsneeker_api.services import repo_branches
from cloudsneeker_api.services.repo_branches import (
    RepositoryBranchError,
    branch_label,
    head_branch,
    list_repository_branches,
    normalize_branch,
    parse_remote_refs,
    run_branch,
)
from cloudsneeker_api.services.sast import run_opengrep_scan, validate_sast_config
from cloudsneeker_api.services.trivy import (
    TrivyHubError,
    checkout_ssh_repository,
    validate_target_config,
)
from dulwich.client import LsRemoteResult

HTTPS_URL = "https://bitbucket.org/acme/shop.git"
SSH_URL = "git@bitbucket.org:acme/shop.git"
TOKEN = "tok-secret-123"
LIMITS = engine.engine_limits()


def _provider(uid=HTTPS_URL, secret=None):
    provider = MagicMock()
    provider.uid = uid
    provider.provider = "iac"
    provider.secret.secret = secret or {}
    return provider


def _fake_clone(head="ref: refs/heads/main"):
    def clone(url, target, *args, **kwargs):
        git_dir = Path(target, ".git")
        git_dir.mkdir(parents=True, exist_ok=True)
        branch = kwargs.get("branch")
        value = f"ref: refs/heads/{branch}" if branch else head
        (git_dir / "HEAD").write_text(value + "\n", encoding="utf-8")
        Path(target, "app.py").write_text("print(1)\n", encoding="utf-8")

    return clone


class TestNormalizeBranch:
    @pytest.mark.parametrize(
        "value, expected",
        [
            ("main", "main"),
            ("  release/2026.11  ", "release/2026.11"),
            ("refs/heads/feature/login", "feature/login"),
            ("", ""),
            (None, ""),
        ],
    )
    def test_accepts_branch_names(self, value, expected):
        assert normalize_branch(value) == expected

    @pytest.mark.parametrize(
        "value",
        [
            "-upload-pack=evil",
            "../etc",
            "a..b",
            "topic.lock",
            "topic/",
            "a b",
            "a//b",
            "x@{1}",
            "a" * 201,
            42,
        ],
    )
    def test_rejects_unsafe_names(self, value):
        with pytest.raises(ValueError):
            normalize_branch(value)


class TestParseRemoteRefs:
    def test_default_branch_comes_first(self):
        result = LsRemoteResult(
            {
                b"HEAD": b"1" * 40,
                b"refs/heads/feature/x": b"2" * 40,
                b"refs/heads/develop": b"3" * 40,
                b"refs/heads/main": b"1" * 40,
                b"refs/tags/v1": b"4" * 40,
                b"refs/pull/1/head": b"5" * 40,
            },
            {b"HEAD": b"refs/heads/main"},
        )
        listing = parse_remote_refs(result)
        assert listing.branches == ["main", "develop", "feature/x"]
        assert listing.default_branch == "main"
        assert listing.truncated is False

    def test_plain_ref_mapping_has_no_default(self):
        listing = parse_remote_refs({b"refs/heads/b": b"1", b"refs/heads/A": b"2"})
        assert listing.branches == ["A", "b"]
        assert listing.default_branch == ""

    def test_long_listings_are_truncated(self):
        refs = {f"refs/heads/b{index:03d}".encode(): b"1" for index in range(5)}
        with patch.object(repo_branches, "MAX_BRANCHES", 3):
            listing = parse_remote_refs(LsRemoteResult(refs, {}))
        assert listing.branches == ["b000", "b001", "b002"]
        assert listing.truncated is True


class TestListRepositoryBranches:
    def test_lists_a_real_repository(self, tmp_path):
        from dulwich import porcelain

        source = tmp_path / "source"
        repo = porcelain.init(str(source))
        (source / "README").write_text("hi", encoding="utf-8")
        porcelain.add(str(source), [str(source / "README")])
        porcelain.commit(
            str(source), message=b"init", author=b"a <a@b>", committer=b"a <a@b>"
        )
        porcelain.branch_create(str(source), "develop")
        repo.close()
        default = head_branch(source)

        listing = list_repository_branches(str(source), _provider(uid=str(source)))

        assert listing.branches[0] == default
        assert listing.default_branch == default
        assert "develop" in listing.branches

    def test_uses_the_provider_token_and_redacts_it(self):
        provider = _provider(secret={"access_token": TOKEN, "username": "jane"})
        with patch(
            "cloudsneeker_api.services.repo_branches.git_ls_remote",
            side_effect=Exception(f"401 for https://jane:{TOKEN}@bitbucket.org"),
        ) as mock_ls:
            with pytest.raises(RepositoryBranchError) as error:
                list_repository_branches(HTTPS_URL, provider)
        assert TOKEN in mock_ls.call_args.args[0]
        assert TOKEN not in str(error.value)

    def test_ssh_errors_are_reported(self):
        with patch(
            "cloudsneeker_api.services.repo_branches.git_ls_remote",
            side_effect=GitSshError("The Git server refused the SSH key."),
        ):
            with pytest.raises(RepositoryBranchError, match="refused the SSH key"):
                list_repository_branches(SSH_URL, _provider(uid=SSH_URL))

    def test_needs_a_url(self):
        with pytest.raises(RepositoryBranchError):
            list_repository_branches("", _provider())


class TestLabels:
    @pytest.mark.parametrize(
        "name, branch, expected",
        [
            ("shop", "develop", "shop @ develop"),
            ("shop", "", "shop"),
            ("shop", None, "shop"),
            ("shop @ develop", "develop", "shop @ develop"),
            ("shop (develop)", "develop", "shop (develop)"),
        ],
    )
    def test_branch_label(self, name, branch, expected):
        assert branch_label(name, branch) == expected

    def test_run_branch_prefers_the_recorded_branch(self):
        assert run_branch({"branch": "develop"}, {}, {"branch": "x"}) == "develop"
        assert run_branch({}, {"metadata": {"Branch": "main"}}, {}) == "main"
        assert run_branch({}, {}, {"branch": "release"}) == "release"
        assert run_branch(None, None, None) == ""

    def test_head_branch(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/dev\n")
        assert head_branch(tmp_path) == "dev"
        (tmp_path / ".git" / "HEAD").write_text("a" * 40)
        assert head_branch(tmp_path) == ""
        assert head_branch(tmp_path / "missing") == ""


class TestTargetConfigBranch:
    def test_repository_target_keeps_its_branch(self):
        config = validate_target_config(
            "repo", {"repository_url": SSH_URL, "branch": "refs/heads/develop"}
        )
        assert config["branch"] == "develop"

    def test_sast_repository_target_keeps_its_branch(self):
        config = validate_target_config(
            "sast", {"repository_url": SSH_URL, "branch": "release/1.0"}
        )
        assert config["branch"] == "release/1.0"

    def test_empty_branch_means_the_default_branch(self):
        config = validate_target_config(
            "repo", {"repository_url": SSH_URL, "branch": "  "}
        )
        assert "branch" not in config

    def test_invalid_branch_is_refused(self):
        with pytest.raises(TrivyHubError, match="valid Git branch"):
            validate_target_config(
                "repo", {"repository_url": SSH_URL, "branch": "--exec=x"}
            )

    def test_branch_needs_a_repository(self):
        with pytest.raises(TrivyHubError, match="needs a repository URL"):
            validate_target_config("sbom", {"sbom": "{}", "branch": "main"})


class TestCheckout:
    def test_ssh_checkout_clones_the_branch(self, tmp_path):
        with patch(
            "cloudsneeker_api.services.trivy.git_clone", side_effect=_fake_clone()
        ) as mock_clone:
            branch = checkout_ssh_repository(
                SSH_URL, _provider(uid=SSH_URL), tmp_path / "r", ref="develop"
            )
        assert branch == "develop"
        assert mock_clone.call_args.kwargs["branch"] == "develop"
        assert mock_clone.call_args.kwargs["depth"] == 1
        assert not (tmp_path / "r" / ".git").exists()

    def test_ssh_checkout_names_the_default_branch(self, tmp_path):
        with patch(
            "cloudsneeker_api.services.trivy.git_clone",
            side_effect=_fake_clone("ref: refs/heads/master"),
        ) as mock_clone:
            branch = checkout_ssh_repository(
                SSH_URL, _provider(uid=SSH_URL), tmp_path / "r"
            )
        assert branch == "master"
        assert "branch" not in mock_clone.call_args.kwargs


class TestEngineBranch:
    def test_target_branch_replaces_profile_refs(self):
        options = {"scanners": ["vuln"], "tag": "v1", "commit": "abc"}
        merged = engine.apply_target_branch({"branch": "develop"}, options)
        assert merged == {"scanners": ["vuln"], "branch": "develop"}
        assert engine.apply_target_branch({}, options) is options

    def test_ssh_unit_checks_out_the_branch(self, tmp_path):
        with patch(
            "cloudsneeker_api.services.trivy.git_clone", side_effect=_fake_clone()
        ) as mock_clone:
            (unit,) = engine.prepare_units(
                mode="repo",
                config={"repository_url": SSH_URL},
                provider=_provider(uid=SSH_URL),
                work_dir=tmp_path,
                limits=LIMITS,
                ref="develop",
            )
        assert mock_clone.call_args.kwargs["branch"] == "develop"
        assert unit.subcommand == "filesystem"
        assert unit.branch == "develop"
        assert unit.option_overrides["branch"] is None

    def test_ssh_unit_records_the_default_branch(self, tmp_path):
        with patch(
            "cloudsneeker_api.services.trivy.git_clone",
            side_effect=_fake_clone("ref: refs/heads/master"),
        ):
            (unit,) = engine.prepare_units(
                mode="repo",
                config={"repository_url": SSH_URL},
                provider=_provider(uid=SSH_URL),
                work_dir=tmp_path,
                limits=LIMITS,
            )
        assert unit.branch == "master"

    def test_https_unit_carries_the_branch(self, tmp_path):
        (unit,) = engine.prepare_units(
            mode="repo",
            config={"repository_url": HTTPS_URL},
            provider=_provider(),
            work_dir=tmp_path,
            limits=LIMITS,
            ref="develop",
        )
        assert unit.subcommand == "repository"
        assert unit.branch == "develop"


class TestSastBranch:
    @pytest.fixture(autouse=True)
    def _engine(self, tmp_path, monkeypatch):
        rules = tmp_path / "rules" / "python"
        rules.mkdir(parents=True)
        (rules / "rule.yml").write_text("rules: []\n", encoding="utf-8")
        monkeypatch.setenv("OPENGREP_RULES_DIR", str(tmp_path / "rules"))
        with patch(
            "cloudsneeker_api.services.sast.resolve_opengrep_bin",
            return_value="opengrep",
        ):
            yield

    def _scan(self, config, head="ref: refs/heads/main"):
        process = MagicMock(
            stdout=json.dumps({"results": [], "errors": []}), stderr="", returncode=0
        )
        with (
            patch("dulwich.porcelain.clone", side_effect=_fake_clone(head)) as clone,
            patch(
                "cloudsneeker_api.services.sast.subprocess.run", return_value=process
            ),
        ):
            report = run_opengrep_scan(
                config=validate_sast_config(dict(config)), provider=_provider()
            )
        return report, clone

    def test_scans_the_chosen_branch(self):
        report, clone = self._scan({"repository_url": HTTPS_URL, "branch": "develop"})
        assert clone.call_args.kwargs["branch"] == "develop"
        assert report["cloudsneeker_branch"] == "develop"

    def test_records_the_default_branch(self):
        report, clone = self._scan(
            {"repository_url": HTTPS_URL}, head="ref: refs/heads/trunk"
        )
        assert "branch" not in clone.call_args.kwargs
        assert report["cloudsneeker_branch"] == "trunk"
