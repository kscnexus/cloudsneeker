"""Authenticated HTTPS clone URLs for private Git repositories.

The IaC provider and Trivy Hub repository mode both clone a repository with a
token stored on the provider secret. Each Git host expects a different
username next to the token, so this module builds the userinfo per host.
Default usernames:

* ``github.com`` and GitHub Enterprise (host contains ``github``):
  ``x-access-token``.
* ``gitlab.com`` and self-hosted GitLab (host contains ``gitlab``): ``oauth2``.
* ``bitbucket.org``: ``x-token-auth`` for repository / workspace access
  tokens; pass ``username`` for an app password.
* Bitbucket Server / Data Center (host contains ``bitbucket``):
  ``x-token-auth`` for project / repository HTTP access tokens; pass
  ``username`` for a personal HTTP access token.
* Azure DevOps (``dev.azure.com``, ``*.visualstudio.com``): ``pat``.
* Any other host: ``x-access-token``.

A ``username``, when given, replaces the default on every host.

The generic default is ``x-access-token`` because the most common enterprise
host on a custom domain is GitHub Enterprise, and Gitea / Forgejo accept a
token as the password with any username. Hosts that need a real account name
(Bitbucket Server personal tokens, generic forges) take the optional
``username``.

Only ``https://`` URLs get credentials. Any other scheme, or an empty token,
returns the URL unchanged. Userinfo already in the URL (Azure DevOps adds
``<org>@``) is replaced. Nothing here logs.

The module imports only the standard library.
"""

from __future__ import annotations

from urllib.parse import quote, urlsplit, urlunsplit

GITHUB_USERNAME = "x-access-token"
GITLAB_USERNAME = "oauth2"
BITBUCKET_TOKEN_USERNAME = "x-token-auth"
AZURE_DEVOPS_USERNAME = "pat"
GENERIC_USERNAME = "x-access-token"

REDACTED = "***"


def git_host_kind(host: str) -> str:
    """Classify a Git host name.

    Args:
        host: Host name without port or userinfo, any case.

    Returns:
        One of ``"github"``, ``"gitlab"``, ``"bitbucket_cloud"``,
        ``"bitbucket_server"``, ``"azure_devops"`` or ``"generic"``.
    """
    host = (host or "").lower().strip(".")
    if host == "bitbucket.org" or host.endswith(".bitbucket.org"):
        return "bitbucket_cloud"
    if host == "dev.azure.com" or host.endswith(".visualstudio.com"):
        return "azure_devops"
    if "github" in host:
        return "github"
    if "gitlab" in host:
        return "gitlab"
    if "bitbucket" in host:
        return "bitbucket_server"
    return "generic"


def default_username(host: str) -> str:
    """Return the username paired with a bare token for ``host``.

    Args:
        host: Host name without port or userinfo.

    Returns:
        The userinfo username documented in the module table.
    """
    kind = git_host_kind(host)
    if kind == "github":
        return GITHUB_USERNAME
    if kind == "gitlab":
        return GITLAB_USERNAME
    if kind in ("bitbucket_cloud", "bitbucket_server"):
        return BITBUCKET_TOKEN_USERNAME
    if kind == "azure_devops":
        return AZURE_DEVOPS_USERNAME
    return GENERIC_USERNAME


def _host_port(netloc: str) -> str:
    """Return ``host[:port]`` from a netloc, dropping any userinfo."""
    return netloc.rsplit("@", 1)[-1]


def strip_userinfo(repository_url: str) -> str:
    """Return ``repository_url`` without ``user[:password]@``.

    Args:
        repository_url: Any URL.

    Returns:
        The URL with userinfo removed; non-URLs are returned unchanged.
    """
    try:
        parts = urlsplit(repository_url)
    except ValueError:
        return repository_url
    if "@" not in parts.netloc:
        return repository_url
    return urlunsplit(parts._replace(netloc=_host_port(parts.netloc)))


def authenticated_clone_url(
    repository_url: str, token: str | None, username: str | None = None
) -> str:
    """Build an HTTPS clone URL that carries ``token`` for the repository host.

    Args:
        repository_url: Repository URL, for example
            ``https://bitbucket.org/acme/app.git``.
        token: Access token, personal access token, or app password.
        username: Optional account name. Defaults per host (module docstring).

    Returns:
        ``https://<user>:<token>@host/path`` with both parts URL-encoded, or
        ``repository_url`` unchanged when there is no token or the URL is not
        ``https``.
    """
    if not token or not repository_url:
        return repository_url
    try:
        parts = urlsplit(repository_url.strip())
    except ValueError:
        return repository_url
    if parts.scheme.lower() != "https" or not parts.hostname:
        return repository_url

    user = (username or "").strip() or default_username(parts.hostname)
    userinfo = f"{quote(user, safe='')}:{quote(str(token), safe='')}"
    netloc = f"{userinfo}@{_host_port(parts.netloc)}"
    return urlunsplit(parts._replace(scheme="https", netloc=netloc))


def iac_clone_url(
    repository_url: str,
    github_username: str | None = None,
    personal_access_token: str | None = None,
    oauth_app_token: str | None = None,
    username: str | None = None,
) -> str:
    """Pick the IaC provider's credentials and build the clone URL.

    Mirrors the IaC provider's precedence: a GitHub username with a personal
    access token first, then the OAuth/access token with the optional
    ``username``.

    Args:
        repository_url: Repository URL to clone.
        github_username: Username paired with ``personal_access_token``.
        personal_access_token: Personal access token.
        oauth_app_token: OAuth app token or API ``access_token``.
        username: Optional account name stored on the provider secret.

    Returns:
        The authenticated clone URL, or ``repository_url`` without a token.
    """
    if github_username and personal_access_token:
        return authenticated_clone_url(
            repository_url, personal_access_token, github_username
        )
    token = oauth_app_token or personal_access_token
    return authenticated_clone_url(repository_url, token, username)


def redact(text: str, *secrets: str | None) -> str:
    """Replace every secret (raw and URL-encoded) in ``text`` with ``***``.

    Args:
        text: Message that may contain secrets.
        *secrets: Tokens or authenticated URLs to hide. Empty values are skipped.

    Returns:
        The redacted text.
    """
    result = str(text)
    for secret in sorted({str(s) for s in secrets if s}, key=len, reverse=True):
        result = result.replace(secret, REDACTED)
        encoded = quote(secret, safe="")
        if encoded != secret:
            result = result.replace(encoded, REDACTED)
    return result


def redact_exception(error: BaseException, *secrets: str | None) -> BaseException:
    """Return ``error``, or a copy whose message no longer contains ``secrets``.

    Args:
        error: Exception raised by a Git client.
        *secrets: Tokens or authenticated URLs to hide.

    Returns:
        ``error`` itself when its message is clean; otherwise a new exception
        of the same class (``RuntimeError`` if the class cannot be rebuilt
        from a message) with the redacted message and the original traceback.
    """
    message = str(error)
    clean = redact(message, *secrets)
    if clean == message:
        return error
    try:
        replacement = type(error)(clean)
    except Exception:  # noqa: BLE001 - some exception types need extra args
        replacement = RuntimeError(clean)
    if str(replacement) != clean:
        replacement = RuntimeError(clean)
    return replacement.with_traceback(error.__traceback__)
