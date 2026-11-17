"""GitHub connection as the source of code repositories.

A GitHub provider (the organization or account connection used for posture
checks) already holds a token or a GitHub App. Its repositories can be
imported as code repository sources (IaC providers) without entering the
token again:

* :func:`list_repositories` lists what the connection can read.
* :func:`import_repositories` creates one IaC provider per chosen repository
  and links it to the connection (``RepositoryConnection``).
* :func:`linked_credentials` gives a linked repository the connection's
  credentials when it has none of its own: the token of a token connection,
  or a short-lived installation token of a GitHub App connection.

A token connection's token is also copied to the repository's own secret, so
every path that reads provider secrets works; the copy is refreshed when the
connection's secret changes (``signals``). A GitHub App token expires within
the hour, so it is never copied; it is minted when a scan needs it.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass
from typing import Any

import requests
from cloudsneeker.git_auth import redact

logger = logging.getLogger(__name__)

API_URL = "https://api.github.com"
TIMEOUT_SECONDS = 20
PAGE_SIZE = 100
MAX_PAGES = 30  # 3,000 repositories
MAX_IMPORT = 500

CODE_UNAUTHORIZED = "unauthorized"
CODE_UNREACHABLE = "unreachable"
CODE_NOT_GITHUB = "not_github"
CODE_NO_CREDENTIALS = "no_credentials"
CODE_INVALID = "invalid"

KIND_TOKEN = "token"
KIND_APP = "app"


class GitHubSourceError(Exception):
    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ConnectionCredentials:
    """How a GitHub connection authenticates.

    Attributes:
        kind: ``token`` (personal access or OAuth token) or ``app``.
        token: Token usable for the API and for HTTPS clones.
    """

    kind: str
    token: str


@dataclass(frozen=True)
class GitHubRepository:
    full_name: str
    clone_url: str
    ssh_url: str
    private: bool
    archived: bool
    default_branch: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _secret(provider) -> dict[str, Any]:
    try:
        secret = provider.secret
    except Exception:  # noqa: BLE001 - no secret row
        return {}
    return (secret.secret if secret is not None else None) or {}


def _app_jwt(app_id: str, private_key: str) -> str:
    import jwt

    now = int(time.time())
    return jwt.encode(
        {"iat": now - 60, "exp": now + 540, "iss": str(app_id)},
        private_key,
        algorithm="RS256",
    )


def _request(method: str, url: str, token: str, *, scheme: str = "Bearer", **kwargs):
    try:
        response = requests.request(
            method,
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"{scheme} {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=TIMEOUT_SECONDS,
            allow_redirects=False,
            **kwargs,
        )
    except requests.RequestException as error:
        raise GitHubSourceError(
            redact(f"GitHub could not be reached: {type(error).__name__}.", token),
            CODE_UNREACHABLE,
        ) from None
    if response.status_code in (401, 403):
        raise GitHubSourceError(
            "GitHub rejected the connection's credentials. Check that they can "
            "read repositories.",
            CODE_UNAUTHORIZED,
        )
    if response.status_code >= 400:
        raise GitHubSourceError(
            f"GitHub answered HTTP {response.status_code}.", CODE_UNREACHABLE
        )
    return response


def _installation_token(app_id: str, private_key: str, owner: str) -> str:
    """Installation token of a GitHub App for the connection's account."""
    try:
        app_token = _app_jwt(app_id, private_key)
    except Exception:  # noqa: BLE001 - malformed key
        raise GitHubSourceError(
            "The GitHub App key of the connection could not be read.",
            CODE_NO_CREDENTIALS,
        ) from None
    installations = _request(
        "GET", f"{API_URL}/app/installations", app_token, params={"per_page": 100}
    ).json()
    if not isinstance(installations, list) or not installations:
        raise GitHubSourceError(
            "The GitHub App is not installed on any account.", CODE_NO_CREDENTIALS
        )
    chosen = next(
        (
            item
            for item in installations
            if str(((item or {}).get("account") or {}).get("login", "")).lower()
            == owner.lower()
        ),
        installations[0],
    )
    payload = _request(
        "POST",
        f"{API_URL}/app/installations/{chosen['id']}/access_tokens",
        app_token,
    ).json()
    token = str((payload or {}).get("token") or "")
    if not token:
        raise GitHubSourceError(
            "GitHub returned no installation token.", CODE_UNREACHABLE
        )
    return token


def connection_credentials(connection) -> ConnectionCredentials:
    """Credentials of a GitHub provider.

    Raises:
        GitHubSourceError: Not a GitHub provider, or no usable credentials.
    """
    if getattr(connection, "provider", "") != "github":
        raise GitHubSourceError(
            "The connection is not a GitHub provider.", CODE_NOT_GITHUB
        )
    secret = _secret(connection)
    token = secret.get("personal_access_token") or secret.get("oauth_app_token")
    if token:
        return ConnectionCredentials(kind=KIND_TOKEN, token=str(token))
    if secret.get("github_app_id") and secret.get("github_app_key"):
        return ConnectionCredentials(
            kind=KIND_APP,
            token=_installation_token(
                str(secret["github_app_id"]),
                str(secret["github_app_key"]),
                str(connection.uid or ""),
            ),
        )
    raise GitHubSourceError(
        "The GitHub connection has no token or GitHub App saved.", CODE_NO_CREDENTIALS
    )


def _parse_repository(item: dict[str, Any]) -> GitHubRepository | None:
    full_name = str(item.get("full_name") or "")
    clone_url = str(item.get("clone_url") or "")
    if not full_name or not clone_url.startswith("https://"):
        return None
    return GitHubRepository(
        full_name=full_name,
        clone_url=clone_url,
        ssh_url=str(item.get("ssh_url") or ""),
        private=bool(item.get("private")),
        archived=bool(item.get("archived")),
        default_branch=str(item.get("default_branch") or ""),
    )


def list_repositories(connection) -> list[GitHubRepository]:
    """Repositories the connection can read; its own account's first.

    Raises:
        GitHubSourceError: GitHub refused or could not be reached.
    """
    credentials = connection_credentials(connection)
    owner = str(connection.uid or "").lower()
    found: dict[str, GitHubRepository] = {}
    for page in range(1, MAX_PAGES + 1):
        if credentials.kind == KIND_APP:
            payload = _request(
                "GET",
                f"{API_URL}/installation/repositories",
                credentials.token,
                params={"per_page": PAGE_SIZE, "page": page},
            ).json()
            items = (payload or {}).get("repositories") or []
        else:
            items = _request(
                "GET",
                f"{API_URL}/user/repos",
                credentials.token,
                params={
                    "per_page": PAGE_SIZE,
                    "page": page,
                    "affiliation": "owner,collaborator,organization_member",
                    "sort": "full_name",
                },
            ).json()
        if not isinstance(items, list):
            raise GitHubSourceError(
                "GitHub returned an unexpected response.", CODE_UNREACHABLE
            )
        for item in items:
            repository = _parse_repository(item if isinstance(item, dict) else {})
            if repository:
                found[repository.full_name.lower()] = repository
        if len(items) < PAGE_SIZE:
            break
    return sorted(
        found.values(),
        key=lambda repo: (
            repo.full_name.split("/")[0].lower() != owner,
            repo.full_name.lower(),
        ),
    )


def normalize_url(url: str) -> str:
    """Compare repository URLs without scheme case, ``.git`` or a slash."""
    value = str(url or "").strip().lower().rstrip("/")
    return value[:-4] if value.endswith(".git") else value


def linked_credentials(provider) -> tuple[str, str | None] | None:
    """``(token, username)`` from the connection a repository was imported
    from, or ``None`` when it was not imported from one.

    Never raises: a scan with no credentials still reaches public
    repositories, and its clone error says what is wrong.
    """
    from uuid import UUID

    from cloudsneeker_api.models import RepositoryConnection

    try:
        provider_id = UUID(str(getattr(provider, "id", "")))
    except ValueError:
        return None
    try:
        link = (
            RepositoryConnection.objects.filter(repository_id=provider_id)
            .select_related("connection", "connection__secret")
            .first()
        )
    except Exception:  # noqa: BLE001 - a lookup failure must not stop a scan
        logger.exception("Connection lookup failed for %s", provider_id)
        return None
    if link is None:
        return None
    try:
        credentials = connection_credentials(link.connection)
    except GitHubSourceError as error:
        logger.warning(
            "Connection credentials unavailable for %s: %s", provider.id, error
        )
        return None
    # GitHub accepts any user name with a token over HTTPS.
    return credentials.token, "x-access-token"


def _managed_secret(token: str) -> dict[str, str]:
    return {"access_token": token}


def import_repositories(
    *, tenant_id: str, connection_id: str, clone_urls: list[str]
) -> dict[str, Any]:
    """Create a code repository source per chosen repository of a connection.

    A repository already added (same URL) is linked to the connection
    instead, keeping its own secret.

    Returns:
        ``{"created": [names], "linked": [names], "skipped": [urls]}``.

    Raises:
        GitHubSourceError: Unknown connection, too many repositories, or GitHub
            could not list them.
    """
    from api.db_utils import rls_transaction
    from api.models import Provider, ProviderSecret
    from cloudsneeker_api.models import RepositoryConnection

    wanted = list(dict.fromkeys(str(url).strip() for url in clone_urls or [] if url))
    if not wanted:
        raise GitHubSourceError("Choose at least one repository.", CODE_INVALID)
    if len(wanted) > MAX_IMPORT:
        raise GitHubSourceError(
            f"Import at most {MAX_IMPORT} repositories at a time.", CODE_INVALID
        )
    with rls_transaction(tenant_id):
        connection = (
            Provider.objects.filter(
                tenant_id=tenant_id, id=connection_id, provider="github"
            )
            .select_related("secret")
            .first()
        )
    if connection is None:
        raise GitHubSourceError("GitHub connection not found.", CODE_NOT_GITHUB)

    credentials = connection_credentials(connection)
    listed = {
        normalize_url(repo.clone_url): repo for repo in list_repositories(connection)
    }
    created: list[str] = []
    linked: list[str] = []
    skipped: list[str] = []
    with rls_transaction(tenant_id):
        existing = {
            normalize_url(provider.uid): provider
            for provider in Provider.objects.filter(
                tenant_id=tenant_id, provider=Provider.ProviderChoices.IAC
            )
        }
        for url in wanted:
            repository = listed.get(normalize_url(url))
            if repository is None:
                skipped.append(url)
                continue
            provider = existing.get(normalize_url(repository.clone_url))
            if provider is None:
                provider = Provider.objects.create(
                    tenant_id=tenant_id,
                    provider=Provider.ProviderChoices.IAC,
                    uid=repository.clone_url,
                    alias=repository.full_name[:100],
                )
                managed = credentials.kind == KIND_TOKEN
                if managed:
                    secret = ProviderSecret(
                        tenant_id=tenant_id,
                        provider=provider,
                        name="From the GitHub connection",
                        secret_type=ProviderSecret.TypeChoices.STATIC,
                    )
                    secret.secret = _managed_secret(credentials.token)
                    secret.save()
                existing[normalize_url(repository.clone_url)] = provider
                created.append(repository.full_name)
            else:
                managed = False
                linked.append(repository.full_name)
            RepositoryConnection.objects.update_or_create(
                tenant_id=tenant_id,
                repository=provider,
                defaults={
                    "connection": connection,
                    "full_name": repository.full_name,
                    "secret_managed": managed,
                },
            )
    return {"created": created, "linked": linked, "skipped": skipped}


def sync_managed_secrets(connection) -> int:
    """Copy a token connection's new token to the repositories it manages.

    Returns:
        The number of repository secrets updated.
    """
    from api.models import ProviderSecret
    from cloudsneeker_api.models import RepositoryConnection

    secret = _secret(connection)
    token = secret.get("personal_access_token") or secret.get("oauth_app_token")
    if not token:
        return 0
    updated = 0
    links = RepositoryConnection.objects.filter(
        tenant_id=connection.tenant_id, connection=connection, secret_managed=True
    ).values_list("repository_id", flat=True)
    for row in ProviderSecret.objects.filter(
        tenant_id=connection.tenant_id, provider_id__in=list(links)
    ):
        row.secret = _managed_secret(str(token))
        row.save(update_fields=["_secret", "updated_at"])
        updated += 1
    return updated
