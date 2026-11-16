"""Repository sources that borrow a token from the tenant's GitHub connection."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from api.models import Provider
from cloudsneeker_api import github_connection
from cloudsneeker_api.github_connection import (
    GITHUB_TOKEN_USERNAME,
    GithubConnectionError,
    apply_github_connection,
    connection_token,
    github_connection_scan_kwargs,
    github_connection_test_kwargs,
    github_owner,
    mint_installation_token,
)

REPOSITORY_URL = "https://github.com/acme/app"
INSTALLATION_TOKEN = "ghs_minted_installation_token"
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nkey\n-----END RSA PRIVATE KEY-----"


def _source(uid: str = REPOSITORY_URL, secret: dict | None = None):
    return SimpleNamespace(
        id="source-1",
        tenant_id="tenant-1",
        provider=Provider.ProviderChoices.IAC.value,
        uid=uid,
        secret=SimpleNamespace(secret=secret if secret is not None else {}),
    )


def _github_provider(secret: dict):
    return SimpleNamespace(
        provider=Provider.ProviderChoices.GITHUB.value,
        uid="acme",
        secret=SimpleNamespace(secret=secret),
    )


def _installation(login: str, installation_id: int = 7):
    return SimpleNamespace(id=installation_id, raw_data={"account": {"login": login}})


class TestGithubOwner:
    @pytest.mark.parametrize(
        "url, owner",
        [
            ("https://github.com/acme/app", "acme"),
            ("https://github.com/acme/app.git", "acme"),
            ("https://GitHub.com/Acme/app/", "Acme"),
            ("https://github.com:443/acme/app", "acme"),
        ],
    )
    def test_returns_the_owner_of_a_github_https_url(self, url, owner):
        assert github_owner(url) == owner

    @pytest.mark.parametrize(
        "url",
        [
            "",
            None,
            "http://github.com/acme/app",
            "git@github.com:acme/app.git",
            "ssh://git@github.com/acme/app.git",
            "https://github.com/acme",
            "https://gitlab.com/acme/app",
            "https://github.com.evil.example/acme/app",
            "https://evil.example/github.com/acme/app",
            "https://user:pass@github.com/acme/app",
            "https://github.com:8443/acme/app",
        ],
    )
    def test_rejects_anything_that_is_not_github_over_https(self, url):
        assert github_owner(url) is None


class TestApplyGithubConnection:
    def test_adds_the_saved_personal_access_token(self):
        provider = _github_provider({"personal_access_token": "github_pat_saved"})
        with patch.object(
            github_connection, "find_github_provider", return_value=provider
        ) as find:
            secret = apply_github_connection(_source(), {})

        find.assert_called_once_with("tenant-1", "acme")
        assert secret == {
            "access_token": "github_pat_saved",
            "username": GITHUB_TOKEN_USERNAME,
        }

    def test_mints_an_installation_token_for_github_app_credentials(self):
        provider = _github_provider(
            {"github_app_id": 123, "github_app_key_content": PRIVATE_KEY}
        )
        with (
            patch.object(
                github_connection, "find_github_provider", return_value=provider
            ),
            patch.object(
                github_connection,
                "mint_installation_token",
                return_value=INSTALLATION_TOKEN,
            ) as mint,
        ):
            secret = apply_github_connection(_source(), {})

        mint.assert_called_once_with(123, PRIVATE_KEY, "acme")
        assert secret["access_token"] == INSTALLATION_TOKEN

    @pytest.mark.parametrize(
        "own", [{"access_token": "own-token"}, {"ssh_private_key": "own-key"}]
    )
    def test_keeps_a_source_that_has_its_own_credential(self, own):
        with patch.object(github_connection, "find_github_provider") as find:
            assert apply_github_connection(_source(secret=own), own) == own

        find.assert_not_called()

    def test_ignores_repositories_on_other_hosts(self):
        with patch.object(github_connection, "find_github_provider") as find:
            source = _source(uid="https://gitlab.com/acme/app")
            assert apply_github_connection(source, {}) == {}

        find.assert_not_called()

    def test_ignores_providers_that_are_not_repository_sources(self):
        source = _source()
        source.provider = Provider.ProviderChoices.AWS.value
        with patch.object(github_connection, "find_github_provider") as find:
            assert apply_github_connection(source, {}) == {}

        find.assert_not_called()

    def test_leaves_the_secret_alone_without_a_github_connection(self):
        with patch.object(github_connection, "find_github_provider", return_value=None):
            assert apply_github_connection(_source(), {"repository_url": "x"}) == {
                "repository_url": "x"
            }

    def test_does_not_change_the_stored_secret(self):
        stored = {"repository_url": REPOSITORY_URL}
        provider = _github_provider({"oauth_app_token": "gho_saved"})
        with patch.object(
            github_connection, "find_github_provider", return_value=provider
        ):
            apply_github_connection(_source(secret=stored), stored)

        assert stored == {"repository_url": REPOSITORY_URL}


class TestConnectionToken:
    def test_returns_nothing_without_a_usable_credential(self):
        assert connection_token(_github_provider({}), "acme") == ""


class TestMintInstallationToken:
    def _integration(self, installations):
        integration = MagicMock()
        integration.get_installations.return_value = installations
        integration.get_access_token.return_value = SimpleNamespace(
            token=INSTALLATION_TOKEN
        )
        return integration

    def test_asks_for_a_read_only_token_of_the_owner_installation(self):
        integration = self._integration(
            [_installation("other", 1), _installation("Acme", 7)]
        )
        with (
            patch("github.GithubIntegration", return_value=integration),
            patch("github.Auth.AppAuth"),
        ):
            token = mint_installation_token("123", PRIVATE_KEY, "acme")

        assert token == INSTALLATION_TOKEN
        integration.get_access_token.assert_called_once_with(
            7, permissions={"contents": "read"}
        )

    def test_says_when_the_app_is_not_installed_on_the_owner(self):
        integration = self._integration([_installation("other")])
        with (
            patch("github.GithubIntegration", return_value=integration),
            patch("github.Auth.AppAuth"),
            pytest.raises(GithubConnectionError, match="not installed on 'acme'"),
        ):
            mint_installation_token(123, PRIVATE_KEY, "acme")

    def test_never_puts_the_private_key_in_the_error(self):
        with (
            patch("github.Auth.AppAuth", side_effect=ValueError(PRIVATE_KEY)),
            pytest.raises(GithubConnectionError) as raised,
        ):
            mint_installation_token(123, PRIVATE_KEY, "acme")

        assert "PRIVATE KEY" not in str(raised.value)


class TestScanAndConnectionKwargs:
    def test_scan_gets_the_borrowed_token(self):
        provider = _github_provider({"personal_access_token": "github_pat_saved"})
        with patch.object(
            github_connection, "find_github_provider", return_value=provider
        ):
            assert github_connection_scan_kwargs(_source()) == {
                "oauth_app_token": "github_pat_saved",
                "username": GITHUB_TOKEN_USERNAME,
            }

    def test_scan_keeps_the_source_token(self):
        source = _source(secret={"access_token": "own-token"})
        assert github_connection_scan_kwargs(source) == {}

    def test_scan_runs_without_a_token_when_the_connection_fails(self):
        with patch.object(
            github_connection,
            "apply_github_connection",
            side_effect=GithubConnectionError("not installed"),
        ):
            assert github_connection_scan_kwargs(_source()) == {}

    def test_scan_runs_without_a_token_when_the_lookup_breaks(self):
        with patch.object(
            github_connection,
            "find_github_provider",
            side_effect=RuntimeError("database unavailable"),
        ):
            assert github_connection_scan_kwargs(_source()) == {}

    def test_connection_test_gets_the_borrowed_token(self):
        provider = _github_provider({"personal_access_token": "github_pat_saved"})
        with patch.object(
            github_connection, "find_github_provider", return_value=provider
        ):
            failure, kwargs = github_connection_test_kwargs(_source())

        assert failure is None
        assert kwargs == {
            "access_token": "github_pat_saved",
            "username": GITHUB_TOKEN_USERNAME,
        }

    def test_connection_test_reports_why_the_connection_failed(self):
        with patch.object(
            github_connection,
            "apply_github_connection",
            side_effect=GithubConnectionError("not installed"),
        ):
            failure, kwargs = github_connection_test_kwargs(_source())

        assert failure.is_connected is False
        assert "not installed" in str(failure.error)
        assert kwargs == {}


class TestRepositoryCredentials:
    def test_clone_uses_the_borrowed_token(self):
        from cloudsneeker_api.services.trivy import _repo_credentials

        provider = _github_provider({"personal_access_token": "github_pat_saved"})
        with patch.object(
            github_connection, "find_github_provider", return_value=provider
        ):
            assert _repo_credentials(_source()) == (
                "github_pat_saved",
                GITHUB_TOKEN_USERNAME,
            )

    def test_clone_fails_with_the_reason_when_the_connection_fails(self):
        from cloudsneeker_api.services import trivy

        with (
            patch.object(
                trivy,
                "apply_github_connection",
                side_effect=GithubConnectionError("not installed"),
            ),
            pytest.raises(trivy.TrivyHubError, match="not installed"),
        ):
            trivy._repo_credentials(_source())
