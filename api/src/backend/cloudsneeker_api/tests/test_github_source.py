"""GitHub connection as the source of code repositories.

The first classes run without a database (GitHub is faked); the last ones
use it.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from cloudsneeker_api.services import github_source
from cloudsneeker_api.services.github_source import (
    GitHubSourceError,
    connection_credentials,
    list_repositories,
    normalize_url,
)


def _connection(secret, uid="acme"):
    return SimpleNamespace(
        id="c1",
        provider="github",
        uid=uid,
        tenant_id="t1",
        secret=SimpleNamespace(secret=secret),
    )


def _response(status_code=200, payload=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    return response


def _repo(full_name, private=False):
    return {
        "full_name": full_name,
        "clone_url": f"https://github.com/{full_name}.git",
        "ssh_url": f"git@github.com:{full_name}.git",
        "private": private,
        "archived": False,
        "default_branch": "main",
    }


class TestCredentials:
    def test_token_connections(self):
        assert connection_credentials(
            _connection({"personal_access_token": "ghp_1"})
        ) == github_source.ConnectionCredentials("token", "ghp_1")
        assert (
            connection_credentials(_connection({"oauth_app_token": "gho_1"})).token
            == "gho_1"
        )

    def test_app_connection_mints_an_installation_token(self):
        with patch.object(
            github_source, "_installation_token", return_value="ghs_1"
        ) as mint:
            credentials = connection_credentials(
                _connection({"github_app_id": "7", "github_app_key": "KEY"})
            )
        assert credentials == github_source.ConnectionCredentials("app", "ghs_1")
        mint.assert_called_once_with("7", "KEY", "acme")

    def test_missing_credentials_and_other_providers(self):
        with pytest.raises(GitHubSourceError) as error:
            connection_credentials(_connection({}))
        assert error.value.code == github_source.CODE_NO_CREDENTIALS
        with pytest.raises(GitHubSourceError):
            connection_credentials(SimpleNamespace(provider="aws"))

    def test_installation_of_the_connection_account_is_used(self):
        calls = []

        def fake(method, url, token, **kwargs):
            calls.append((method, url))
            if url.endswith("/app/installations"):
                return _response(
                    payload=[
                        {"id": 1, "account": {"login": "other"}},
                        {"id": 2, "account": {"login": "ACME"}},
                    ]
                )
            return _response(payload={"token": "ghs_2"})

        with (
            patch.object(github_source, "_app_jwt", return_value="jwt"),
            patch.object(github_source, "_request", side_effect=fake),
        ):
            assert github_source._installation_token("7", "KEY", "acme") == "ghs_2"
        assert calls[-1] == (
            "POST",
            "https://api.github.com/app/installations/2/access_tokens",
        )


class TestListRepositories:
    def test_token_listing_pages_and_puts_own_account_first(self):
        pages = [
            [_repo(f"zeta/r{i}") for i in range(github_source.PAGE_SIZE)],
            [_repo("acme/web"), {"full_name": "bad"}],
        ]
        with patch(
            "requests.request", side_effect=[_response(payload=p) for p in pages]
        ):
            repos = list_repositories(_connection({"personal_access_token": "t"}))
        assert repos[0].full_name == "acme/web"
        assert len(repos) == github_source.PAGE_SIZE + 1

    def test_app_listing_reads_installation_repositories(self):
        with (
            patch.object(github_source, "_installation_token", return_value="ghs"),
            patch(
                "requests.request",
                return_value=_response(payload={"repositories": [_repo("acme/api")]}),
            ) as request,
        ):
            repos = list_repositories(
                _connection({"github_app_id": "7", "github_app_key": "K"})
            )
        assert [repo.full_name for repo in repos] == ["acme/api"]
        assert request.call_args.args[1].endswith("/installation/repositories")

    def test_rejected_token(self):
        with patch("requests.request", return_value=_response(401)):
            with pytest.raises(GitHubSourceError) as error:
                list_repositories(_connection({"personal_access_token": "t"}))
        assert error.value.code == github_source.CODE_UNAUTHORIZED
        assert "t" not in str(error.value).split()


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("https://github.com/acme/web.git", "https://GitHub.com/acme/web"),
        ("https://github.com/acme/web/", "https://github.com/acme/web.git"),
    ],
)
def test_normalize_url(a, b):
    assert normalize_url(a) == normalize_url(b)


def test_repo_credentials_fall_back_to_the_connection():
    from cloudsneeker_api.services.trivy import _repo_credentials

    provider = SimpleNamespace(id="p1", secret=SimpleNamespace(secret={}))
    with patch.object(
        github_source, "linked_credentials", return_value=("ghs", "x-access-token")
    ):
        assert _repo_credentials(provider) == ("ghs", "x-access-token")
    own = SimpleNamespace(
        id="p1", secret=SimpleNamespace(secret={"access_token": "own"})
    )
    with patch.object(github_source, "linked_credentials") as linked:
        assert _repo_credentials(own) == ("own", None)
    linked.assert_not_called()


@pytest.mark.django_db
class TestImport:
    def test_import_creates_linked_sources_with_a_managed_secret(self, github_provider):
        from api.models import Provider, ProviderSecret
        from cloudsneeker_api.models import RepositoryConnection

        secret = ProviderSecret(
            tenant_id=github_provider.tenant_id,
            provider=github_provider,
            secret_type="static",
        )
        secret.secret = {"personal_access_token": "ghp_old"}
        secret.save()
        listing = [
            github_source.GitHubRepository(
                full_name="acme/web",
                clone_url="https://github.com/acme/web.git",
                ssh_url="",
                private=True,
                archived=False,
                default_branch="main",
            )
        ]
        with patch.object(github_source, "list_repositories", return_value=listing):
            result = github_source.import_repositories(
                tenant_id=str(github_provider.tenant_id),
                connection_id=str(github_provider.id),
                clone_urls=["https://github.com/acme/web", "https://github.com/x/y"],
            )
        assert result == {
            "created": ["acme/web"],
            "linked": [],
            "skipped": ["https://github.com/x/y"],
        }
        repo = Provider.objects.get(
            provider="iac", uid="https://github.com/acme/web.git"
        )
        assert repo.alias == "acme/web"
        assert repo.secret.secret == {"access_token": "ghp_old"}
        link = RepositoryConnection.objects.get(repository=repo)
        assert link.connection_id == github_provider.id and link.secret_managed

        secret.secret = {"personal_access_token": "ghp_new"}
        secret.save()
        assert github_source.sync_managed_secrets(github_provider) == 1
        repo.refresh_from_db()
        assert ProviderSecret.objects.get(provider=repo).secret == {
            "access_token": "ghp_new"
        }

    def test_endpoints(self, authenticated_client, github_provider):
        from django.urls import reverse

        response = authenticated_client.get(reverse("appsec-source-connections-list"))
        assert response.status_code == 200
        ids = [item["id"] for item in response.json()["data"]]
        assert str(github_provider.id) in ids

        with patch(
            "cloudsneeker_api.views_sources.list_repositories",
            side_effect=GitHubSourceError("nope", github_source.CODE_UNAUTHORIZED),
        ):
            response = authenticated_client.get(
                reverse(
                    "appsec-source-connections-repositories",
                    kwargs={"pk": github_provider.id},
                )
            )
        assert response.status_code == 400

        with patch(
            "cloudsneeker_api.views_sources.import_repositories",
            return_value={"created": ["acme/web"], "linked": [], "skipped": []},
        ) as importer:
            response = authenticated_client.post(
                reverse(
                    "appsec-source-connections-import",
                    kwargs={"pk": github_provider.id},
                ),
                data=json.dumps(
                    {
                        "data": {
                            "type": "x",
                            "attributes": {
                                "clone_urls": ["https://github.com/acme/web"]
                            },
                        }
                    }
                ),
                content_type="application/vnd.api+json",
            )
        assert response.status_code == 200
        assert response.json()["data"]["attributes"]["created"] == ["acme/web"]
        importer.assert_called_once()
