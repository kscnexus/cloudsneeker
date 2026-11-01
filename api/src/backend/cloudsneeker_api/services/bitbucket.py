"""List the repositories in a Bitbucket workspace or project.

The Bitbucket import page adds many repositories as IaC providers at once. This
module only reads the repository list; the UI then creates each provider and
its secret through the existing ``/providers`` and ``/providers/secrets`` APIs,
so plan limits, roles, and the audit log apply to every repository.

Two hosts are supported:

* Bitbucket Cloud (``server_url`` empty): ``GET /2.0/repositories/{workspace}``
  on ``api.bitbucket.org``.
* Bitbucket Server / Data Center (``server_url`` set): ``GET
  /rest/api/1.0/projects/{project}/repos``, or ``/rest/api/1.0/repos`` for
  every repository the token can read.

Authentication:

* Access token only (workspace, project or repository access token on Cloud;
  HTTP access token on Server): ``Authorization: Bearer <token>``. The clone
  username stays empty so :mod:`cloudsneeker.git_auth` pairs the token with
  ``x-token-auth``.
* ``username`` plus token (Atlassian account email and API token on Cloud;
  user name and personal HTTP access token on Server): HTTP basic auth. On
  Cloud the clone username is ``x-bitbucket-api-token-auth``; on Server it is
  the user name.

A Server URL is user input, so it must use ``https`` and resolve only to
public addresses, and redirects are never followed. Nothing here logs the
token.

The module imports only ``requests``, the standard library, and
:mod:`cloudsneeker.git_auth`, so it is testable without Django.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit, urlunsplit

import requests
from cloudsneeker.git_auth import redact, strip_userinfo
from cloudsneeker.git_ssh import is_ssh_url, ssh_host

CLOUD_API = "https://api.bitbucket.org/2.0"
CLOUD_API_TOKEN_CLONE_USERNAME = "x-bitbucket-api-token-auth"
PAGE_SIZE = 100
MAX_REPOSITORIES = 1000
TIMEOUT_SECONDS = 15

CLOUD_WORKSPACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
SERVER_PROJECT = re.compile(r"^~?[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

CODE_INVALID = "invalid"
CODE_UNAUTHORIZED = "unauthorized"
CODE_NOT_FOUND = "not_found"
CODE_UNREACHABLE = "unreachable"


class BitbucketError(Exception):
    """A Bitbucket request failed in a way the user can act on."""

    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class BitbucketRepository:
    """One repository, ready to become an IaC provider."""

    name: str
    full_name: str
    repository_url: str
    html_url: str
    ssh_url: str
    project: str
    is_private: bool
    updated_on: str | None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class RepositoryListing:
    """Repositories plus the username to store next to the token."""

    repositories: list[BitbucketRepository]
    clone_username: str
    truncated: bool


def normalize_repository_url(url: str) -> str:
    """Return a comparison key for a repository URL.

    Drops userinfo, a trailing ``/`` and ``.git``, and lowercases the result,
    so ``https://u@bitbucket.org/Acme/App.git`` matches
    ``https://bitbucket.org/acme/app``. An SSH URL becomes
    ``https://<host>/<path>``, so ``git@bitbucket.org:acme/app.git`` matches
    too (Bitbucket Server SSH paths differ from its ``/scm/`` HTTPS paths).

    Args:
        url: Repository URL.

    Returns:
        The normalized key.
    """
    value = (url or "").strip()
    if is_ssh_url(value):
        if value.lower().startswith("ssh://"):
            path = urlsplit(value).path
        else:
            path = value.split(":", 1)[1]
        value = f"https://{ssh_host(value)}/{path.lstrip('/')}"
    value = strip_userinfo(value).rstrip("/")
    if value.lower().endswith(".git"):
        value = value[:-4]
    return value.rstrip("/").lower()


def _is_public_address(address: str) -> bool:
    try:
        return ipaddress.ip_address(address.split("%", 1)[0]).is_global
    except ValueError:
        return False


def validate_server_url(server_url: str) -> str:
    """Check a Bitbucket Server URL and return it without a trailing ``/``.

    Args:
        server_url: Base URL, for example ``https://git.example.com/bitbucket``.

    Returns:
        The base URL.

    Raises:
        BitbucketError: The URL is not ``https``, carries credentials, a query
            or a fragment, or its host resolves to a non-public address.
    """
    try:
        parts = urlsplit((server_url or "").strip())
    except ValueError as error:
        raise BitbucketError(
            "Enter a valid Bitbucket Server URL.", CODE_INVALID
        ) from error
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise BitbucketError(
            "The Bitbucket Server URL must start with https://.", CODE_INVALID
        )
    if "@" in parts.netloc or parts.query or parts.fragment:
        raise BitbucketError(
            "The Bitbucket Server URL must not include credentials, a query or a fragment.",
            CODE_INVALID,
        )
    try:
        port = parts.port or 443
        addresses = {
            info[4][0]
            for info in socket.getaddrinfo(
                parts.hostname, port, type=socket.SOCK_STREAM
            )
        }
    except (OSError, ValueError) as error:
        raise BitbucketError(
            "The Bitbucket Server host could not be resolved.", CODE_UNREACHABLE
        ) from error
    if not addresses or not all(_is_public_address(a) for a in addresses):
        raise BitbucketError(
            "The Bitbucket Server must be reachable on a public address.", CODE_INVALID
        )
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc, parts.path.rstrip("/"), "", "")
    )


def _session(access_token: str, username: str | None) -> requests.Session:
    session = requests.Session()
    session.headers["Accept"] = "application/json"
    if username:
        session.auth = (username, access_token)
    else:
        session.headers["Authorization"] = f"Bearer {access_token}"
    return session


def _get_json(
    session: requests.Session, url: str, params: dict | None, token: str
) -> dict:
    try:
        response = session.get(
            url, params=params, timeout=TIMEOUT_SECONDS, allow_redirects=False
        )
    except requests.RequestException as error:
        raise BitbucketError(
            redact(f"Bitbucket could not be reached: {type(error).__name__}.", token),
            CODE_UNREACHABLE,
        ) from None
    if response.status_code in (401, 403):
        raise BitbucketError(
            "Bitbucket rejected the token. Check that it is valid and can read repositories.",
            CODE_UNAUTHORIZED,
        )
    if response.status_code == 404:
        raise BitbucketError(
            "Bitbucket found no such workspace or project for this token.",
            CODE_NOT_FOUND,
        )
    if response.status_code != 200:
        raise BitbucketError(
            f"Bitbucket answered HTTP {response.status_code}.", CODE_UNREACHABLE
        )
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        raise BitbucketError(
            "Bitbucket returned an unexpected response.", CODE_UNREACHABLE
        )
    return payload


def _ssh_href(links: dict) -> str:
    for link in (links or {}).get("clone") or []:
        href = (link or {}).get("href") or ""
        if (link or {}).get("name") == "ssh" and is_ssh_url(href):
            return href
    return ""


def _clone_href(links: dict, names: tuple[str, ...]) -> str:
    for link in (links or {}).get("clone") or []:
        href = (link or {}).get("href") or ""
        if (link or {}).get("name") in names and href.lower().startswith("https://"):
            return strip_userinfo(href)
    return ""


def _list_cloud(
    session: requests.Session, workspace: str, token: str
) -> tuple[list, bool]:
    url: str | None = f"{CLOUD_API}/repositories/{workspace}"
    params: dict | None = {"pagelen": PAGE_SIZE, "sort": "-updated_on"}
    repositories: list[BitbucketRepository] = []
    while url:
        payload = _get_json(session, url, params, token)
        for item in payload.get("values") or []:
            links = item.get("links") or {}
            clone_url = _clone_href(links, ("https",))
            if not clone_url:
                continue
            repositories.append(
                BitbucketRepository(
                    name=item.get("name") or item.get("slug") or "",
                    full_name=item.get("full_name") or "",
                    repository_url=clone_url,
                    html_url=((links.get("html") or {}).get("href")) or "",
                    ssh_url=_ssh_href(links),
                    project=((item.get("project") or {}).get("name")) or "",
                    is_private=bool(item.get("is_private")),
                    updated_on=item.get("updated_on"),
                )
            )
            if len(repositories) >= MAX_REPOSITORIES:
                return repositories, True
        next_url = payload.get("next")
        # Follow pagination only on the Cloud API host.
        url = (
            next_url
            if isinstance(next_url, str) and next_url.startswith(f"{CLOUD_API}/")
            else None
        )
        params = None
    return repositories, False


def _list_server(
    session: requests.Session, base_url: str, project: str, token: str
) -> tuple[list, bool]:
    path = (
        f"/rest/api/1.0/projects/{project}/repos" if project else "/rest/api/1.0/repos"
    )
    url = f"{base_url}{path}"
    start = 0
    repositories: list[BitbucketRepository] = []
    while True:
        payload = _get_json(session, url, {"limit": PAGE_SIZE, "start": start}, token)
        for item in payload.get("values") or []:
            links = item.get("links") or {}
            clone_url = _clone_href(links, ("http", "https"))
            if not clone_url:
                continue
            item_project = item.get("project") or {}
            slug = item.get("slug") or ""
            self_links = links.get("self")
            html = self_links[0] if isinstance(self_links, list) and self_links else {}
            repositories.append(
                BitbucketRepository(
                    name=item.get("name") or slug,
                    full_name=f"{item_project.get('key', '')}/{slug}".strip("/"),
                    repository_url=clone_url,
                    html_url=(html or {}).get("href") or "",
                    ssh_url=_ssh_href(links),
                    project=item_project.get("name") or item_project.get("key") or "",
                    is_private=not bool(item.get("public")),
                    updated_on=None,
                )
            )
            if len(repositories) >= MAX_REPOSITORIES:
                return repositories, True
        next_start = payload.get("nextPageStart")
        if (
            payload.get("isLastPage", True)
            or not isinstance(next_start, int)
            or next_start <= start
        ):
            return repositories, False
        start = next_start


def list_repositories(
    *,
    access_token: str,
    workspace: str = "",
    username: str = "",
    server_url: str = "",
) -> RepositoryListing:
    """List the repositories a Bitbucket token can read.

    Args:
        access_token: Access token, API token, or HTTP access token.
        workspace: Cloud workspace slug (required on Cloud) or Server project
            key (optional on Server; empty lists every readable repository).
        username: Atlassian account email (Cloud API token) or Server user
            name (personal HTTP access token). Empty for access tokens.
        server_url: Bitbucket Server / Data Center base URL. Empty for Cloud.

    Returns:
        The repositories sorted by full name, the clone username to store
        with the token, and whether the list stopped at
        ``MAX_REPOSITORIES``.

    Raises:
        BitbucketError: Invalid input, or Bitbucket refused or failed.
    """
    access_token = (access_token or "").strip()
    workspace = (workspace or "").strip()
    username = (username or "").strip()
    server_url = (server_url or "").strip()
    if not access_token:
        raise BitbucketError("An access token is required.", CODE_INVALID)

    session = _session(access_token, username or None)
    try:
        if server_url:
            if workspace and not SERVER_PROJECT.match(workspace):
                raise BitbucketError("Enter a valid project key.", CODE_INVALID)
            base_url = validate_server_url(server_url)
            repositories, truncated = _list_server(
                session, base_url, workspace, access_token
            )
            clone_username = username
        else:
            if not CLOUD_WORKSPACE.match(workspace):
                raise BitbucketError("Enter a valid workspace ID.", CODE_INVALID)
            repositories, truncated = _list_cloud(session, workspace, access_token)
            clone_username = CLOUD_API_TOKEN_CLONE_USERNAME if username else ""
    finally:
        session.close()

    repositories.sort(key=lambda repository: repository.full_name.lower())
    return RepositoryListing(
        repositories=repositories,
        clone_username=clone_username,
        truncated=truncated,
    )
