"""GitHub repositories: listing client and API view."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import requests
from cloudsneeker_api.github_connection import GithubConnectionError
from cloudsneeker_api.services import github_repositories
from cloudsneeker_api.services.github_repositories import (
    GITHUB_API,
    MAX_PAGES,
    PAGE_SIZE,
    list_repositories,
)

TOKEN = "github_pat_saved_secret"
INSTALLATION_TOKEN = "ghs_minted_installation_token"


def _provider(secret: dict, uid: str = "acme"):
    return SimpleNamespace(uid=uid, secret=SimpleNamespace(secret=secret))


def _response(status_code=200, payload=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload if payload is not None else []
    return response


def _repo(name: str, owner: str = "acme", private: bool = True):
    return {
        "name": name,
        "full_name": f"{owner}/{name}",
        "private": private,
        "archived": False,
        "default_branch": "main",
        "pushed_at": "2026-11-01T10:00:00Z",
    }


class TestTokenListing:
    @patch.object(github_repositories.requests.Session, "get")
    def test_lists_the_organization_repositories(self, mock_get):
        mock_get.return_value = _response(payload=[_repo("web"), _repo("api")])

        listing = list_repositories(_provider({"personal_access_token": TOKEN}))

        assert [repo.full_name for repo in listing.repositories] == [
            "acme/api",
            "acme/web",
        ]
        assert listing.repositories[0].repository_url == "https://github.com/acme/api"
        assert listing.truncated is False
        url = mock_get.call_args.args[0]
        assert url == f"{GITHUB_API}/orgs/acme/repos"
        assert mock_get.call_args.kwargs["allow_redirects"] is False

    @patch.object(github_repositories.requests.Session, "get")
    def test_falls_back_to_the_user_repositories_of_that_owner(self, mock_get):
        mock_get.side_effect = [
            _response(status_code=404),
            _response(
                payload=[_repo("mine", owner="jane"), _repo("web", owner="acme")]
            ),
        ]

        listing = list_repositories(
            _provider({"personal_access_token": TOKEN}, uid="jane")
        )

        assert [repo.full_name for repo in listing.repositories] == ["jane/mine"]
        assert mock_get.call_args.args[0] == f"{GITHUB_API}/user/repos"

    @patch.object(github_repositories.requests.Session, "get")
    def test_stops_at_the_page_cap(self, mock_get):
        mock_get.side_effect = [
            _response(payload=[_repo(f"r{page}-{index}") for index in range(PAGE_SIZE)])
            for page in range(MAX_PAGES)
        ]

        listing = list_repositories(_provider({"personal_access_token": TOKEN}))

        assert len(listing.repositories) == PAGE_SIZE * MAX_PAGES
        assert listing.truncated is True
        assert mock_get.call_count == MAX_PAGES

    @pytest.mark.parametrize("status_code", [401, 403])
    @patch.object(github_repositories.requests.Session, "get")
    def test_rejected_credential_is_reported(self, mock_get, status_code):
        mock_get.return_value = _response(status_code=status_code)

        with pytest.raises(GithubConnectionError, match="rejected"):
            list_repositories(_provider({"personal_access_token": TOKEN}))

    @patch.object(github_repositories.requests.Session, "get")
    def test_network_error_hides_the_token(self, mock_get):
        mock_get.side_effect = requests.ConnectionError(f"boom {TOKEN}")

        with pytest.raises(GithubConnectionError) as raised:
            list_repositories(_provider({"personal_access_token": TOKEN}))

        assert TOKEN not in str(raised.value)

    def test_requires_a_credential(self):
        with pytest.raises(GithubConnectionError, match="no credential"):
            list_repositories(_provider({}))


class TestAppListing:
    @patch.object(github_repositories.requests.Session, "get")
    def test_lists_what_the_installation_can_read(self, mock_get):
        mock_get.return_value = _response(
            payload={"repositories": [_repo("web"), _repo("other", owner="else")]}
        )
        secret = {"github_app_id": 123, "github_app_key_content": "pem"}

        with patch.object(
            github_repositories, "connection_token", return_value=INSTALLATION_TOKEN
        ):
            listing = list_repositories(_provider(secret))

        assert [repo.full_name for repo in listing.repositories] == ["acme/web"]
        assert mock_get.call_args.args[0] == f"{GITHUB_API}/installation/repositories"


@pytest.mark.django_db
class TestGithubRepositoriesView:
    def _github_provider(self, tenant, secret):
        from api.models import Provider, ProviderSecret

        provider = Provider.objects.create(
            tenant_id=tenant.id, provider="github", uid="acme", alias="acme"
        )
        ProviderSecret.objects.create(
            tenant_id=tenant.id,
            provider=provider,
            secret_type=ProviderSecret.TypeChoices.STATIC,
            secret=secret,
            name="acme",
        )
        return provider

    def _url(self, provider_id):
        from django.urls import reverse

        return reverse("github-repositories", kwargs={"pk": provider_id})

    @patch.object(github_repositories.requests.Session, "get")
    def test_lists_and_flags_existing_sources(
        self, mock_get, authenticated_client, tenants_fixture
    ):
        from api.models import Provider

        tenant = tenants_fixture[0]
        provider = self._github_provider(tenant, {"personal_access_token": TOKEN})
        Provider.objects.create(
            tenant_id=tenant.id,
            provider="iac",
            uid="https://github.com/acme/web.git",
            alias="web",
        )
        mock_get.return_value = _response(payload=[_repo("web"), _repo("api")])

        response = authenticated_client.get(self._url(provider.id))

        assert response.status_code == 200
        body = response.json()
        rows = {row["attributes"]["full_name"]: row for row in body["data"]}
        assert rows["acme/web"]["attributes"]["already_added"] is True
        assert rows["acme/api"]["attributes"]["already_added"] is False
        assert rows["acme/api"]["type"] == "github-repositories"
        assert body["meta"] == {"count": 2, "truncated": False}
        assert TOKEN not in response.content.decode()

    def test_connection_in_another_tenant_is_not_found(
        self, authenticated_client, tenants_fixture
    ):
        provider = self._github_provider(
            tenants_fixture[2], {"personal_access_token": TOKEN}
        )

        response = authenticated_client.get(self._url(provider.id))

        assert response.status_code == 404

    @patch.object(github_repositories.requests.Session, "get")
    def test_github_rejection_is_a_client_error(
        self, mock_get, authenticated_client, tenants_fixture
    ):
        provider = self._github_provider(
            tenants_fixture[0], {"personal_access_token": TOKEN}
        )
        mock_get.return_value = _response(status_code=401)

        response = authenticated_client.get(self._url(provider.id))

        assert response.status_code == 400
        assert response.json()["errors"][0]["code"] == "github_connection_failed"
