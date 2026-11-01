"""Bitbucket workspace import: repository listing client and API view."""

from unittest.mock import MagicMock, patch

import pytest
import requests
from cloudsneeker_api.services import bitbucket
from cloudsneeker_api.services.bitbucket import (
    CLOUD_API,
    CLOUD_API_TOKEN_CLONE_USERNAME,
    CODE_INVALID,
    CODE_NOT_FOUND,
    CODE_UNAUTHORIZED,
    CODE_UNREACHABLE,
    BitbucketError,
    list_repositories,
    normalize_repository_url,
    validate_server_url,
)
from django.urls import reverse

TOKEN = "bb-secret-token"
URL = reverse("bitbucket-repositories")


def _response(status_code=200, payload=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload if payload is not None else {}
    return response


def _cloud_repo(slug, private=True, workspace="acme"):
    return {
        "name": slug.title(),
        "slug": slug,
        "full_name": f"{workspace}/{slug}",
        "is_private": private,
        "updated_on": "2026-10-30T10:00:00+00:00",
        "project": {"name": "Platform"},
        "links": {
            "html": {"href": f"https://bitbucket.org/{workspace}/{slug}"},
            "clone": [
                {
                    "name": "https",
                    "href": f"https://jane@bitbucket.org/{workspace}/{slug}.git",
                },
                {"name": "ssh", "href": f"git@bitbucket.org:{workspace}/{slug}.git"},
            ],
        },
    }


def _server_repo(slug, public=False):
    return {
        "slug": slug,
        "name": slug,
        "public": public,
        "project": {"key": "OPS", "name": "Operations"},
        "links": {
            "self": [
                {"href": f"https://git.example.com/projects/OPS/repos/{slug}/browse"}
            ],
            "clone": [
                {
                    "name": "http",
                    "href": f"https://admin@git.example.com/scm/ops/{slug}.git",
                },
                {
                    "name": "ssh",
                    "href": f"ssh://git@git.example.com:7999/ops/{slug}.git",
                },
            ],
        },
    }


PUBLIC_ADDRINFO = [(2, 1, 6, "", ("104.192.141.1", 443))]


class TestNormalizeRepositoryUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "https://bitbucket.org/acme/app",
            "https://bitbucket.org/acme/app/",
            "https://jane@bitbucket.org/Acme/App.git",
            " https://bitbucket.org/acme/app.git ",
        ],
    )
    def test_equivalent_urls_share_a_key(self, url):
        assert normalize_repository_url(url) == "https://bitbucket.org/acme/app"


class TestCloudListing:
    @patch.object(bitbucket.requests.Session, "get")
    def test_lists_workspace_with_bearer_token(self, mock_get):
        mock_get.return_value = _response(
            payload={"values": [_cloud_repo("web"), _cloud_repo("api", private=False)]}
        )

        listing = list_repositories(access_token=TOKEN, workspace="acme")

        assert [r.full_name for r in listing.repositories] == ["acme/api", "acme/web"]
        api = listing.repositories[0]
        assert api.repository_url == "https://bitbucket.org/acme/api.git"
        assert api.html_url == "https://bitbucket.org/acme/api"
        assert api.project == "Platform"
        assert api.is_private is False
        assert listing.clone_username == ""
        assert listing.truncated is False
        args, kwargs = mock_get.call_args
        assert args[0] == f"{CLOUD_API}/repositories/acme"
        assert kwargs["allow_redirects"] is False

    def test_bearer_header_without_username(self):
        session = bitbucket._session(TOKEN, None)
        assert session.headers["Authorization"] == f"Bearer {TOKEN}"
        assert session.auth is None

    def test_basic_auth_with_username(self):
        session = bitbucket._session(TOKEN, "jane@example.com")
        assert session.auth == ("jane@example.com", TOKEN)
        assert "Authorization" not in session.headers

    @patch.object(bitbucket.requests.Session, "get")
    def test_api_token_uses_static_clone_username(self, mock_get):
        mock_get.return_value = _response(payload={"values": [_cloud_repo("web")]})

        listing = list_repositories(
            access_token=TOKEN, workspace="acme", username="jane@example.com"
        )

        assert listing.clone_username == CLOUD_API_TOKEN_CLONE_USERNAME

    @patch.object(bitbucket.requests.Session, "get")
    def test_follows_next_page_on_cloud_host_only(self, mock_get):
        mock_get.side_effect = [
            _response(
                payload={
                    "values": [_cloud_repo("one")],
                    "next": f"{CLOUD_API}/repositories/acme?page=2",
                }
            ),
            _response(
                payload={
                    "values": [_cloud_repo("two")],
                    "next": "https://attacker.example/steal",
                }
            ),
        ]

        listing = list_repositories(access_token=TOKEN, workspace="acme")

        assert [r.full_name for r in listing.repositories] == ["acme/one", "acme/two"]
        assert mock_get.call_count == 2

    @patch.object(bitbucket.requests.Session, "get")
    def test_stops_at_the_repository_cap(self, mock_get):
        mock_get.return_value = _response(
            payload={
                "values": [_cloud_repo(f"r{i}") for i in range(5)],
                "next": f"{CLOUD_API}/repositories/acme?page=2",
            }
        )

        with patch.object(bitbucket, "MAX_REPOSITORIES", 3):
            listing = list_repositories(access_token=TOKEN, workspace="acme")

        assert len(listing.repositories) == 3
        assert listing.truncated is True
        assert mock_get.call_count == 1

    @patch.object(bitbucket.requests.Session, "get")
    def test_skips_repositories_without_https_clone(self, mock_get):
        repo = _cloud_repo("ssh-only")
        repo["links"]["clone"] = [
            {"name": "ssh", "href": "git@bitbucket.org:acme/x.git"}
        ]
        mock_get.return_value = _response(payload={"values": [repo]})

        assert (
            list_repositories(access_token=TOKEN, workspace="acme").repositories == []
        )

    @pytest.mark.parametrize("workspace", ["", "acme/other", "../etc", "a b"])
    def test_rejects_invalid_workspace(self, workspace):
        with pytest.raises(BitbucketError) as error:
            list_repositories(access_token=TOKEN, workspace=workspace)
        assert error.value.code == CODE_INVALID

    def test_requires_token(self):
        with pytest.raises(BitbucketError) as error:
            list_repositories(access_token="  ", workspace="acme")
        assert error.value.code == CODE_INVALID

    @pytest.mark.parametrize(
        "status_code,code",
        [
            (401, CODE_UNAUTHORIZED),
            (403, CODE_UNAUTHORIZED),
            (404, CODE_NOT_FOUND),
            (500, CODE_UNREACHABLE),
            (302, CODE_UNREACHABLE),
        ],
    )
    @patch.object(bitbucket.requests.Session, "get")
    def test_maps_http_errors(self, mock_get, status_code, code):
        mock_get.return_value = _response(status_code=status_code)

        with pytest.raises(BitbucketError) as error:
            list_repositories(access_token=TOKEN, workspace="acme")

        assert error.value.code == code
        assert TOKEN not in str(error.value)

    @patch.object(bitbucket.requests.Session, "get")
    def test_network_error_hides_token(self, mock_get):
        mock_get.side_effect = requests.ConnectionError(f"failed with {TOKEN}")

        with pytest.raises(BitbucketError) as error:
            list_repositories(access_token=TOKEN, workspace="acme")

        assert error.value.code == CODE_UNREACHABLE
        assert TOKEN not in str(error.value)


class TestServerListing:
    @patch.object(bitbucket.socket, "getaddrinfo", return_value=PUBLIC_ADDRINFO)
    @patch.object(bitbucket.requests.Session, "get")
    def test_lists_project_and_pages(self, mock_get, _addrinfo):
        mock_get.side_effect = [
            _response(
                payload={
                    "values": [_server_repo("infra")],
                    "isLastPage": False,
                    "nextPageStart": 1,
                }
            ),
            _response(
                payload={
                    "values": [_server_repo("docs", public=True)],
                    "isLastPage": True,
                }
            ),
        ]

        listing = list_repositories(
            access_token=TOKEN,
            workspace="OPS",
            server_url="https://git.example.com/",
            username="svc-scan",
        )

        assert [r.full_name for r in listing.repositories] == ["OPS/docs", "OPS/infra"]
        infra = listing.repositories[1]
        assert infra.repository_url == "https://git.example.com/scm/ops/infra.git"
        assert infra.is_private is True
        assert listing.repositories[0].is_private is False
        assert listing.clone_username == "svc-scan"
        first_url = mock_get.call_args_list[0].args[0]
        assert first_url == "https://git.example.com/rest/api/1.0/projects/OPS/repos"
        assert mock_get.call_args_list[1].kwargs["params"]["start"] == 1

    @patch.object(bitbucket.socket, "getaddrinfo", return_value=PUBLIC_ADDRINFO)
    @patch.object(bitbucket.requests.Session, "get")
    def test_without_project_lists_all_readable_repos(self, mock_get, _addrinfo):
        mock_get.return_value = _response(payload={"values": [], "isLastPage": True})

        list_repositories(
            access_token=TOKEN, server_url="https://git.example.com/bitbucket"
        )

        assert (
            mock_get.call_args.args[0]
            == "https://git.example.com/bitbucket/rest/api/1.0/repos"
        )


class TestValidateServerUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "http://git.example.com",
            "ftp://git.example.com",
            "https://user:pass@git.example.com",
            "https://git.example.com?x=1",
            "not a url",
        ],
    )
    def test_rejects_unsafe_urls(self, url):
        with pytest.raises(BitbucketError) as error:
            validate_server_url(url)
        assert error.value.code == CODE_INVALID

    @pytest.mark.parametrize(
        "address", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1", "::1"]
    )
    def test_rejects_non_public_addresses(self, address):
        with patch.object(
            bitbucket.socket,
            "getaddrinfo",
            return_value=[(2, 1, 6, "", (address, 443))],
        ):
            with pytest.raises(BitbucketError) as error:
                validate_server_url("https://git.example.com")
        assert error.value.code == CODE_INVALID

    def test_rejects_when_any_address_is_private(self):
        with patch.object(
            bitbucket.socket,
            "getaddrinfo",
            return_value=PUBLIC_ADDRINFO + [(2, 1, 6, "", ("10.0.0.1", 443))],
        ):
            with pytest.raises(BitbucketError):
                validate_server_url("https://git.example.com")

    def test_unresolvable_host(self):
        with patch.object(bitbucket.socket, "getaddrinfo", side_effect=OSError("nope")):
            with pytest.raises(BitbucketError) as error:
                validate_server_url("https://git.example.com")
        assert error.value.code == CODE_UNREACHABLE

    def test_keeps_context_path(self):
        with patch.object(
            bitbucket.socket, "getaddrinfo", return_value=PUBLIC_ADDRINFO
        ):
            assert (
                validate_server_url("HTTPS://git.example.com:8443/bitbucket/")
                == "https://git.example.com:8443/bitbucket"
            )


def _body(**attributes):
    return {"data": {"type": "bitbucket-repository-listings", "attributes": attributes}}


@pytest.mark.django_db
class TestBitbucketRepositoriesView:
    @patch.object(bitbucket.requests.Session, "get")
    def test_lists_and_flags_existing_providers(
        self, mock_get, authenticated_client, tenants_fixture
    ):
        from api.models import Provider

        Provider.objects.create(
            tenant_id=tenants_fixture[0].id,
            provider="iac",
            uid="https://bitbucket.org/acme/web",
            alias="web",
        )
        mock_get.return_value = _response(
            payload={"values": [_cloud_repo("web"), _cloud_repo("api")]}
        )

        response = authenticated_client.post(
            URL,
            data=_body(workspace="acme", access_token=TOKEN),
            content_type="application/vnd.api+json",
        )

        assert response.status_code == 200
        body = response.json()
        rows = {row["attributes"]["full_name"]: row for row in body["data"]}
        assert rows["acme/web"]["attributes"]["already_added"] is True
        assert rows["acme/api"]["attributes"]["already_added"] is False
        assert rows["acme/api"]["type"] == "bitbucket-repositories"
        assert body["meta"] == {"count": 2, "clone_username": "", "truncated": False}
        assert TOKEN not in response.content.decode()

    @patch.object(bitbucket.requests.Session, "get")
    def test_existing_provider_in_other_tenant_is_not_flagged(
        self, mock_get, authenticated_client, tenants_fixture
    ):
        from api.models import Provider

        Provider.objects.create(
            tenant_id=tenants_fixture[1].id,
            provider="iac",
            uid="https://bitbucket.org/acme/web",
        )
        mock_get.return_value = _response(payload={"values": [_cloud_repo("web")]})

        response = authenticated_client.post(
            URL,
            data=_body(workspace="acme", access_token=TOKEN),
            content_type="application/vnd.api+json",
        )

        assert response.json()["data"][0]["attributes"]["already_added"] is False

    @patch.object(bitbucket.requests.Session, "get")
    def test_accepts_plain_json(self, mock_get, authenticated_client):
        mock_get.return_value = _response(payload={"values": []})

        response = authenticated_client.post(
            URL,
            data={"workspace": "acme", "access_token": TOKEN},
            content_type="application/json",
        )

        assert response.status_code == 200
        assert response.json()["data"] == []

    @patch.object(bitbucket.requests.Session, "get")
    def test_bitbucket_rejection_is_a_client_error(
        self, mock_get, authenticated_client
    ):
        mock_get.return_value = _response(status_code=401)

        response = authenticated_client.post(
            URL,
            data=_body(workspace="acme", access_token=TOKEN),
            content_type="application/vnd.api+json",
        )

        assert response.status_code == 400
        assert response.json()["errors"][0]["code"] == CODE_UNAUTHORIZED

    def test_invalid_input(self, authenticated_client):
        response = authenticated_client.post(
            URL,
            data=_body(workspace="", access_token=TOKEN),
            content_type="application/vnd.api+json",
        )

        assert response.status_code == 400
        assert response.json()["errors"][0]["code"] == CODE_INVALID

    def test_requires_manage_providers(self, authenticated_client_no_permissions_rbac):
        response = authenticated_client_no_permissions_rbac.post(
            URL,
            data=_body(workspace="acme", access_token=TOKEN),
            content_type="application/vnd.api+json",
        )

        assert response.status_code == 403

    def test_requires_authentication(self, client):
        response = client.post(
            URL,
            data=_body(workspace="acme", access_token=TOKEN),
            content_type="application/vnd.api+json",
        )

        assert response.status_code == 401
