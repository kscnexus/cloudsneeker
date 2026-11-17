"""List the repositories a tenant's GitHub connection can read.

The GitHub repositories page adds repositories as repository sources (IaC
providers) without a token of their own; scans then borrow one from the
GitHub connection (:mod:`cloudsneeker_api.github_connection`).

* GitHub App credentials: ``GET /installation/repositories`` with an
  installation token, so the list is exactly what the app was given.
* Personal access token or OAuth App token: ``GET /orgs/{owner}/repos``, or
  ``GET /user/repos`` filtered to ``owner`` when ``owner`` is a user.

Requests only go to ``api.github.com``. Error messages never carry a token.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import quote

import requests
from api.models import Provider
from cloudsneeker_api.github_connection import (
    GithubConnectionError,
    connection_token,
)

GITHUB_API = "https://api.github.com"
PAGE_SIZE = 100
MAX_PAGES = 10
TIMEOUT_SECONDS = 20


@dataclass(frozen=True)
class GithubRepository:
    """One repository, ready to become a repository source."""

    name: str
    full_name: str
    repository_url: str
    is_private: bool
    is_archived: bool
    default_branch: str
    updated_on: str | None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class GithubRepositoryListing:
    repositories: list[GithubRepository]
    truncated: bool


def _is_app_secret(secret: dict[str, Any]) -> bool:
    has_token = secret.get("personal_access_token") or secret.get("oauth_app_token")
    return bool(not has_token and secret.get("github_app_id"))


def _get(session: requests.Session, path: str, params: dict[str, Any]):
    try:
        response = session.get(
            f"{GITHUB_API}{path}",
            params=params,
            timeout=TIMEOUT_SECONDS,
            allow_redirects=False,
        )
    except requests.RequestException as error:
        raise GithubConnectionError(
            f"GitHub could not be reached ({type(error).__name__})."
        ) from None
    if response.status_code in (401, 403):
        raise GithubConnectionError(
            "GitHub rejected the connection's credential. Check that it is "
            "valid and can read repositories."
        )
    return response


def _json(response) -> Any:
    if response.status_code != 200:
        raise GithubConnectionError(f"GitHub answered HTTP {response.status_code}.")
    try:
        return response.json()
    except ValueError:
        raise GithubConnectionError("GitHub returned an unexpected response.") from None


def _repository(item: dict[str, Any]) -> GithubRepository | None:
    full_name = str(item.get("full_name") or "")
    if full_name.count("/") != 1:
        return None
    return GithubRepository(
        name=str(item.get("name") or full_name.split("/")[1]),
        full_name=full_name,
        repository_url=f"https://github.com/{full_name}",
        is_private=bool(item.get("private")),
        is_archived=bool(item.get("archived")),
        default_branch=str(item.get("default_branch") or ""),
        updated_on=item.get("pushed_at") or item.get("updated_at"),
    )


def _pages(session: requests.Session, path: str, params: dict[str, Any], key=None):
    """Return ``(items, truncated)`` over at most ``MAX_PAGES`` pages.

    Returns ``(None, False)`` when the first page is a 404, so the caller can
    try another endpoint.
    """
    items: list[dict[str, Any]] = []
    for page in range(1, MAX_PAGES + 1):
        response = _get(session, path, {**params, "per_page": PAGE_SIZE, "page": page})
        if response.status_code == 404 and page == 1:
            return None, False
        payload = _json(response)
        batch = payload.get(key) if key and isinstance(payload, dict) else payload
        if not isinstance(batch, list):
            raise GithubConnectionError("GitHub returned an unexpected response.")
        items.extend(item for item in batch if isinstance(item, dict))
        if len(batch) < PAGE_SIZE:
            return items, False
    return items, True


def list_repositories(github_provider: Provider) -> GithubRepositoryListing:
    """List the repositories of a GitHub provider's account.

    Args:
        github_provider: GitHub provider with its secret loaded; its uid is
            the user or organization login.

    Returns:
        Repositories owned by that account, sorted by name.

    Raises:
        GithubConnectionError: The connection has no usable credential, or
            GitHub refused or failed the request.
    """
    owner = str(github_provider.uid or "").strip()
    secret_row = getattr(github_provider, "secret", None)
    secret = dict(secret_row.secret or {}) if secret_row is not None else {}
    token = connection_token(github_provider, owner)
    if not owner or not token:
        raise GithubConnectionError(
            "This GitHub connection has no credential. Add one with Update Credentials."
        )

    session = requests.Session()
    session.headers.update(
        {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
    )
    try:
        if _is_app_secret(secret):
            items, truncated = _pages(
                session, "/installation/repositories", {}, key="repositories"
            )
        else:
            items, truncated = _pages(
                session, f"/orgs/{quote(owner, safe='')}/repos", {"type": "all"}
            )
            if items is None:
                items, truncated = _pages(
                    session, "/user/repos", {"affiliation": "owner"}
                )
    finally:
        session.close()

    repositories = [
        repository
        for repository in (_repository(item) for item in items or [])
        if repository and repository.full_name.split("/")[0].lower() == owner.lower()
    ]
    repositories.sort(key=lambda repository: repository.full_name.lower())
    return GithubRepositoryListing(repositories=repositories, truncated=truncated)
