"""Per-host clone URLs for private repositories and the IaC provider hooks."""

from unittest import mock

import pytest

from cloudsneeker.git_auth import (
    authenticated_clone_url,
    default_username,
    git_host_kind,
    iac_clone_url,
    redact,
    redact_exception,
    strip_userinfo,
)
from prowler.providers.iac.exceptions.exceptions import IacRepositoryCloneError
from prowler.providers.iac.iac_provider import IacProvider

TOKEN = "tok-123"


class TestGitHostKind:
    @pytest.mark.parametrize(
        ("host", "kind"),
        [
            ("github.com", "github"),
            ("GitHub.acme.com", "github"),
            ("gitlab.com", "gitlab"),
            ("gitlab.internal.acme.com", "gitlab"),
            ("bitbucket.org", "bitbucket_cloud"),
            ("bitbucket.acme.com", "bitbucket_server"),
            ("dev.azure.com", "azure_devops"),
            ("acme.visualstudio.com", "azure_devops"),
            ("git.acme.com", "generic"),
        ],
    )
    def test_classifies_hosts(self, host: str, kind: str):
        assert git_host_kind(host) == kind

    def test_default_usernames(self):
        assert default_username("github.com") == "x-access-token"
        assert default_username("gitlab.com") == "oauth2"
        assert default_username("bitbucket.org") == "x-token-auth"
        assert default_username("bitbucket.acme.com") == "x-token-auth"
        assert default_username("dev.azure.com") == "pat"
        assert default_username("git.acme.com") == "x-access-token"


class TestAuthenticatedCloneUrl:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            (
                "https://github.com/acme/app.git",
                f"https://x-access-token:{TOKEN}@github.com/acme/app.git",
            ),
            (
                "https://github.acme.com/acme/app",
                f"https://x-access-token:{TOKEN}@github.acme.com/acme/app",
            ),
            (
                "https://gitlab.com/acme/app.git",
                f"https://oauth2:{TOKEN}@gitlab.com/acme/app.git",
            ),
            (
                "https://gitlab.acme.com:8443/group/sub/app.git",
                f"https://oauth2:{TOKEN}@gitlab.acme.com:8443/group/sub/app.git",
            ),
            (
                "https://bitbucket.org/acme/app.git",
                f"https://x-token-auth:{TOKEN}@bitbucket.org/acme/app.git",
            ),
            (
                "https://bitbucket.acme.com/scm/prj/app.git",
                f"https://x-token-auth:{TOKEN}@bitbucket.acme.com/scm/prj/app.git",
            ),
            (
                "https://acme@dev.azure.com/acme/proj/_git/app",
                f"https://pat:{TOKEN}@dev.azure.com/acme/proj/_git/app",
            ),
            (
                "https://git.acme.com/team/app.git",
                f"https://x-access-token:{TOKEN}@git.acme.com/team/app.git",
            ),
        ],
    )
    def test_default_userinfo_per_host(self, url: str, expected: str):
        assert authenticated_clone_url(url, TOKEN) == expected

    def test_username_overrides_default(self):
        assert (
            authenticated_clone_url(
                "https://bitbucket.org/acme/app.git", "app-pass", "jane"
            )
            == "https://jane:app-pass@bitbucket.org/acme/app.git"
        )
        assert (
            authenticated_clone_url(
                "https://dev.azure.com/acme/proj/_git/app", TOKEN, "jane@acme.com"
            )
            == f"https://jane%40acme.com:{TOKEN}@dev.azure.com/acme/proj/_git/app"
        )

    def test_url_encodes_token(self):
        url = authenticated_clone_url("https://gitlab.com/a/b", "p@ss:w/rd")
        assert url == "https://oauth2:p%40ss%3Aw%2Frd@gitlab.com/a/b"

    def test_replaces_existing_userinfo(self):
        assert (
            authenticated_clone_url("https://old:secret@github.com/a/b", TOKEN)
            == f"https://x-access-token:{TOKEN}@github.com/a/b"
        )

    @pytest.mark.parametrize(
        "url",
        [
            "http://github.com/a/b",
            "git@github.com:a/b.git",
            "ssh://git@github.com/a/b.git",
            "",
        ],
    )
    def test_leaves_non_https_urls_unchanged(self, url: str):
        assert authenticated_clone_url(url, TOKEN) == url

    def test_no_token_leaves_url_unchanged(self):
        url = "https://bitbucket.org/acme/app.git"
        assert authenticated_clone_url(url, None) == url
        assert authenticated_clone_url(url, "") == url


class TestIacCloneUrl:
    def test_github_username_and_pat(self):
        assert (
            iac_clone_url("https://github.com/a/b", "user", "pat", None)
            == "https://user:pat@github.com/a/b"
        )

    def test_oauth_token_with_stored_username(self):
        assert (
            iac_clone_url("https://bitbucket.org/a/b", None, None, "pw", "jane")
            == "https://jane:pw@bitbucket.org/a/b"
        )

    def test_no_credentials(self):
        assert iac_clone_url("https://gitlab.com/a/b") == "https://gitlab.com/a/b"


class TestRedaction:
    def test_redacts_raw_and_encoded_secrets(self):
        message = "failed https://x:p%40ss@host/a and p@ss"
        assert redact(message, "p@ss") == "failed https://x:***@host/a and ***"

    def test_skips_empty_secrets(self):
        assert redact("nothing here", None, "") == "nothing here"

    def test_strip_userinfo(self):
        assert strip_userinfo("https://u:p@host/a") == "https://host/a"
        assert strip_userinfo("https://host/a") == "https://host/a"

    def test_redact_exception_keeps_class_and_traceback(self):
        try:
            raise ValueError(f"bad url https://oauth2:{TOKEN}@gitlab.com/a")
        except ValueError as error:
            clean = redact_exception(error, TOKEN)
        assert isinstance(clean, ValueError)
        assert TOKEN not in str(clean)
        assert clean.__traceback__ is not None

    def test_redact_exception_returns_clean_error_unchanged(self):
        error = ValueError("no secret")
        assert redact_exception(error, TOKEN) is error


class TestIacProviderHooks:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            (
                "https://gitlab.com/acme/app.git",
                f"https://oauth2:{TOKEN}@gitlab.com/acme/app.git",
            ),
            (
                "https://bitbucket.org/acme/app.git",
                f"https://x-token-auth:{TOKEN}@bitbucket.org/acme/app.git",
            ),
            (
                "https://dev.azure.com/acme/p/_git/app",
                f"https://pat:{TOKEN}@dev.azure.com/acme/p/_git/app",
            ),
        ],
    )
    def test_clone_and_connection_test_use_the_same_url(self, url, expected):
        provider = IacProvider()
        with (
            mock.patch(
                "prowler.providers.iac.iac_provider.porcelain.clone"
            ) as mock_clone,
            mock.patch("tempfile.mkdtemp", return_value="/tmp/fake-dir"),
            mock.patch.object(provider, "_detect_branch_name", return_value="main"),
        ):
            provider._clone_repository(url, oauth_app_token=TOKEN)
        mock_clone.assert_called_with(expected, "/tmp/fake-dir", depth=1)

        with mock.patch(
            "prowler.providers.iac.iac_provider.porcelain.ls_remote"
        ) as mock_ls_remote:
            connection = IacProvider.test_connection(
                scan_repository_url=url, access_token=TOKEN
            )
        assert connection.is_connected
        mock_ls_remote.assert_called_once_with(expected)

    def test_username_kwarg_reaches_clone_and_connection_test(self):
        url = "https://bitbucket.org/acme/app.git"
        expected = "https://jane:app-pass@bitbucket.org/acme/app.git"
        with (
            mock.patch(
                "prowler.providers.iac.iac_provider.porcelain.clone"
            ) as mock_clone,
            mock.patch("tempfile.mkdtemp", return_value="/tmp/fake-dir"),
            mock.patch.object(
                IacProvider, "_detect_branch_name", return_value="main"
            ),
        ):
            provider = IacProvider(
                scan_repository_url=url,
                oauth_app_token="app-pass",
                username="jane",
            )
        assert provider.git_username == "jane"
        mock_clone.assert_called_with(expected, "/tmp/fake-dir", depth=1)

        with mock.patch(
            "prowler.providers.iac.iac_provider.porcelain.ls_remote"
        ) as mock_ls_remote:
            IacProvider.test_connection(
                scan_repository_url=url, access_token="app-pass", username="jane"
            )
        mock_ls_remote.assert_called_once_with(expected)

    def test_connection_error_never_contains_token(self):
        url = "https://git.acme.com/team/app.git"
        with mock.patch(
            "prowler.providers.iac.iac_provider.porcelain.ls_remote",
            side_effect=Exception(f"boom https://x-access-token:{TOKEN}@git.acme.com"),
        ):
            connection = IacProvider.test_connection(
                scan_repository_url=url, access_token=TOKEN
            )
        assert not connection.is_connected
        assert TOKEN not in str(connection.error)

    def test_clone_error_never_contains_token(self):
        provider = IacProvider()
        with (
            mock.patch(
                "prowler.providers.iac.iac_provider.porcelain.clone",
                side_effect=Exception(f"denied https://oauth2:{TOKEN}@gitlab.com/a"),
            ),
            mock.patch("tempfile.mkdtemp", return_value="/tmp/fake-dir"),
        ):
            with pytest.raises(IacRepositoryCloneError) as exc_info:
                provider._clone_repository(
                    "https://gitlab.com/a", oauth_app_token=TOKEN
                )
        assert TOKEN not in str(exc_info.value)
