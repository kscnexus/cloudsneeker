"""Repository access through the tenant's GitHub connection.

A repository source (IaC provider) for ``https://github.com/<owner>/<repo>``
that stores no credential of its own borrows one from the tenant's GitHub
provider whose uid is ``<owner>``:

* a personal access token or OAuth App token is used as saved;
* GitHub App credentials mint an installation token for ``<owner>``, limited
  to ``contents: read`` and valid for one hour, at scan time.

The token is only resolved for ``github.com`` over HTTPS and only for the
owner the GitHub provider was added for, so it cannot be sent to another host
or used for another account. Error messages never carry a token or key.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlsplit

from api.db_utils import rls_transaction
from api.models import Provider

logger = logging.getLogger(__name__)

GITHUB_HOST = "github.com"
# User name GitHub documents for token authentication over HTTPS.
GITHUB_TOKEN_USERNAME = "x-access-token"
# Keys that mean the repository source brings its own credential.
OWN_CREDENTIAL_KEYS = ("access_token", "ssh_private_key")
INSTALLATION_TOKEN_PERMISSIONS = {"contents": "read"}


class GithubConnectionError(Exception):
    """Raised when the GitHub connection cannot produce a repository token."""


def github_owner(repository_url: str | None) -> str | None:
    """Return the account that owns a ``github.com`` HTTPS repository URL.

    Args:
        repository_url: Repository URL, for example
            ``https://github.com/acme/app.git``.

    Returns:
        The owner (user or organization login), or ``None`` when the URL is
        not an HTTPS ``github.com`` repository URL.
    """
    try:
        parts = urlsplit(str(repository_url or "").strip())
    except ValueError:
        return None
    if parts.scheme.lower() != "https":
        return None
    if (parts.hostname or "").lower() != GITHUB_HOST or parts.port not in (None, 443):
        return None
    if parts.username or parts.password:
        return None
    segments = [segment for segment in parts.path.split("/") if segment]
    if len(segments) < 2:
        return None
    return segments[0]


def has_own_credentials(secret: dict[str, Any] | None) -> bool:
    """Return True when a repository source stores its own token or SSH key."""
    return any((secret or {}).get(key) for key in OWN_CREDENTIAL_KEYS)


def find_github_provider(tenant_id: str, owner: str) -> Provider | None:
    """Return the tenant's GitHub provider added for ``owner``, if any.

    Args:
        tenant_id: Tenant that owns the repository source.
        owner: GitHub user or organization login (compared without case).

    Returns:
        The GitHub provider with its secret loaded, or ``None``.
    """
    with rls_transaction(str(tenant_id)):
        return (
            Provider.objects.filter(
                tenant_id=tenant_id,
                provider=Provider.ProviderChoices.GITHUB.value,
                uid__iexact=owner,
            )
            .select_related("secret")
            .order_by("inserted_at")
            .first()
        )


def mint_installation_token(app_id: Any, private_key: str, owner: str) -> str:
    """Return a one-hour, read-only installation token for ``owner``.

    Args:
        app_id: GitHub App ID.
        private_key: GitHub App private key (PEM content).
        owner: Account the app must be installed on.

    Returns:
        The installation access token.

    Raises:
        GithubConnectionError: The app is not installed on ``owner``, lacks
            the Contents permission, or its credentials are rejected.
    """
    from github import Auth, GithubException, GithubIntegration

    try:
        integration = GithubIntegration(auth=Auth.AppAuth(int(app_id), private_key))
        for installation in integration.get_installations():
            login = (installation.raw_data.get("account") or {}).get("login") or ""
            if login.lower() == owner.lower():
                return integration.get_access_token(
                    installation.id, permissions=INSTALLATION_TOKEN_PERMISSIONS
                ).token
    except GithubException as error:
        raise GithubConnectionError(
            f"GitHub rejected the GitHub App credentials (HTTP {error.status}). "
            "Check the App ID, the private key, and that the app has the "
            "Contents: Read repository permission."
        ) from None
    except Exception as error:  # noqa: BLE001 - never surface key material
        raise GithubConnectionError(
            f"The GitHub App credentials could not be used ({type(error).__name__})."
        ) from None
    raise GithubConnectionError(
        f"The GitHub App is not installed on '{owner}'. Install it on that "
        "account, or approve the pending installation request."
    )


def connection_token(github_provider: Provider, owner: str) -> str:
    """Return a repository token from a GitHub provider's stored secret.

    Args:
        github_provider: GitHub provider with its secret loaded.
        owner: Account that owns the repository.

    Returns:
        The token, or "" when the provider has no usable credential.

    Raises:
        GithubConnectionError: A GitHub App token could not be minted.
    """
    secret_row = getattr(github_provider, "secret", None)
    secret = dict(secret_row.secret or {}) if secret_row is not None else {}
    token = secret.get("personal_access_token") or secret.get("oauth_app_token")
    if token:
        return str(token)
    app_id = secret.get("github_app_id")
    private_key = secret.get("github_app_key_content") or secret.get("github_app_key")
    if app_id and private_key:
        return mint_installation_token(app_id, str(private_key), owner)
    return ""


def apply_github_connection(
    provider: Provider, secret: dict[str, Any] | None
) -> dict[str, Any]:
    """Return ``secret`` with a token from the GitHub connection when needed.

    Args:
        provider: Repository source (IaC provider); its uid is the
            repository URL.
        secret: Stored secret of the repository source.

    Returns:
        ``secret`` unchanged when the source has its own credential, is not a
        ``github.com`` HTTPS repository, or the tenant has no GitHub provider
        for the owner. Otherwise a copy with ``access_token`` and ``username``
        set.

    Raises:
        GithubConnectionError: The GitHub connection exists but cannot issue
            a token.
    """
    current = dict(secret or {})
    if provider.provider != Provider.ProviderChoices.IAC.value:
        return current
    if has_own_credentials(current):
        return current
    owner = github_owner(provider.uid)
    if not owner:
        return current
    github_provider = find_github_provider(str(provider.tenant_id), owner)
    if github_provider is None:
        return current
    token = connection_token(github_provider, owner)
    if not token:
        return current
    return {**current, "access_token": token, "username": GITHUB_TOKEN_USERNAME}


def _borrowed_token(provider: Provider) -> str:
    """Return the token the GitHub connection adds to a source, or ""."""
    secret_row = getattr(provider, "secret", None)
    stored = dict(secret_row.secret or {}) if secret_row is not None else {}
    if stored.get("access_token"):
        return ""
    return str(apply_github_connection(provider, stored).get("access_token") or "")


def github_connection_scan_kwargs(provider: Provider) -> dict[str, str]:
    """Return the ``IacProvider`` keyword arguments for a borrowed token.

    Args:
        provider: Repository source about to be scanned.

    Returns:
        ``oauth_app_token`` and ``username`` when the GitHub connection
        supplies a token, otherwise an empty mapping. Never raises: without a
        token the scan fails with the Git host's authentication error.
    """
    try:
        token = _borrowed_token(provider)
    except Exception as error:  # noqa: BLE001 - a lookup failure must not stop the scan
        logger.warning("GitHub connection unavailable for %s: %s", provider.id, error)
        return {}
    if not token:
        return {}
    return {"oauth_app_token": token, "username": GITHUB_TOKEN_USERNAME}


def github_connection_test_kwargs(provider: Provider):
    """Return ``(failure, kwargs)`` for a repository source connection test.

    Args:
        provider: Repository source being tested.

    Returns:
        ``(None, kwargs)`` with ``access_token`` and ``username`` when the
        GitHub connection supplies a token (empty when it does not apply), or
        ``(Connection, {})`` with the reason when the connection exists but
        cannot issue a token.
    """
    from prowler.providers.common.models import Connection

    try:
        token = _borrowed_token(provider)
    except GithubConnectionError as error:
        return Connection(is_connected=False, error=error), {}
    if not token:
        return None, {}
    return None, {"access_token": token, "username": GITHUB_TOKEN_USERNAME}
