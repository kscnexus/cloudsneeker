"""Git branches of an Application Security repository source.

Repository (dependency) and static analysis targets read one branch of the
linked IaC provider's repository. A target's ``config.branch`` names it; an
empty value means the repository's default branch. One target scans one
branch, so scanning several branches means one target per branch.

Branches are listed with ``git ls-remote`` (Dulwich) using the provider's
token or SSH key, so the listing works for Bitbucket, GitHub, GitLab, Azure
DevOps and self-hosted servers alike.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from api.models import Provider
from cloudsneeker.git_auth import authenticated_clone_url, redact
from cloudsneeker.git_ssh import GitSshError
from cloudsneeker.git_ssh import ls_remote as git_ls_remote

# Listing more than this many branches is not useful in a picker.
MAX_BRANCHES = 500
MAX_BRANCH_LENGTH = 200

HEADS_PREFIX = "refs/heads/"
# Same character set as the engine's ``--branch`` option (``appsec.options``).
_BRANCH_RE = re.compile(r"^[\w][\w./@+-]{0,199}$")


class RepositoryBranchError(ValueError):
    """The repository's branches could not be listed."""


@dataclass(frozen=True)
class RepositoryBranches:
    """Branches of one repository.

    Attributes:
        branches: Branch names, the default branch first, then by name.
        default_branch: Branch the remote ``HEAD`` points to ("" if unknown).
        truncated: More than ``MAX_BRANCHES`` branches exist.
    """

    branches: list[str] = field(default_factory=list)
    default_branch: str = ""
    truncated: bool = False


def normalize_branch(value: Any) -> str:
    """Return a validated branch name, or "" for none.

    Args:
        value: ``config.branch`` as sent by the client.

    Returns:
        The stripped branch name ("" when empty or ``None``).

    Raises:
        ValueError: Not a string, or not a safe Git branch name. The name is
            passed to Git and the engine, so option-like or path-escaping
            values are refused.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("config.branch must be a branch name.")
    name = value.strip()
    if name.startswith(HEADS_PREFIX):
        name = name[len(HEADS_PREFIX) :]
    if not name:
        return ""
    if (
        not _BRANCH_RE.match(name)
        or ".." in name
        or "//" in name
        or name.endswith((".lock", "/", "."))
        or "@{" in name
    ):
        raise ValueError("config.branch is not a valid Git branch name.")
    return name


def head_branch(repo_dir: Path) -> str:
    """Branch checked out in a clone, read from ``.git/HEAD``.

    Args:
        repo_dir: Clone directory, before its ``.git`` is removed.

    Returns:
        The branch name, or "" when HEAD is detached or unreadable.
    """
    try:
        head = (repo_dir / ".git" / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    prefix = f"ref: {HEADS_PREFIX}"
    return head[len(prefix) :] if head.startswith(prefix) else ""


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value or "")


def parse_remote_refs(result: Any) -> RepositoryBranches:
    """Turn a Dulwich ``ls_remote`` result into branch names.

    Args:
        result: ``LsRemoteResult`` (``refs`` and ``symrefs``) or a plain
            ref mapping from older Dulwich versions.

    Returns:
        The branches, default first.
    """
    refs = getattr(result, "refs", result) or {}
    symrefs = getattr(result, "symrefs", None) or {}
    names = sorted(
        {
            _text(ref)[len(HEADS_PREFIX) :]
            for ref in refs
            if _text(ref).startswith(HEADS_PREFIX)
        }
        - {""},
        key=str.lower,
    )
    head = _text(symrefs.get(b"HEAD") or symrefs.get("HEAD"))
    default = head[len(HEADS_PREFIX) :] if head.startswith(HEADS_PREFIX) else ""
    if default and default not in names:
        default = ""
    if default:
        names.remove(default)
        names.insert(0, default)
    return RepositoryBranches(
        branches=names[:MAX_BRANCHES],
        default_branch=default,
        truncated=len(names) > MAX_BRANCHES,
    )


def list_repository_branches(
    repository_url: str, provider: Provider
) -> RepositoryBranches:
    """List the branches of a repository with the provider's credentials.

    Args:
        repository_url: HTTPS or SSH repository URL (the provider's uid).
        provider: IaC provider holding the token or SSH key.

    Returns:
        The repository's branches.

    Raises:
        RepositoryBranchError: The repository could not be reached or read;
            the message never carries a token.
    """
    from cloudsneeker_api.services.trivy import _repo_credentials, repo_ssh_args

    url = str(repository_url or "").strip()
    if not url:
        raise RepositoryBranchError("The source has no repository URL.")
    token, username = _repo_credentials(provider)
    auth_url = authenticated_clone_url(url, token or None, username)
    secrets = tuple(item for item in (auth_url, token) if item and item != url)
    try:
        result = git_ls_remote(auth_url, *repo_ssh_args(provider))
    except GitSshError as exc:
        raise RepositoryBranchError(str(exc)) from None
    except Exception as exc:  # noqa: BLE001 - never surface a token
        message = redact(str(exc), *secrets) or type(exc).__name__
        raise RepositoryBranchError(
            f"Could not list the repository's branches: {message}"
        ) from None
    return parse_remote_refs(result)


def branch_label(name: str, branch: str | None) -> str:
    """Name of a target with the branch it scans, for titles and file names.

    Args:
        name: Target name.
        branch: Branch scanned ("" or ``None`` when unknown).

    Returns:
        ``name`` when there is no branch or the name already ends with it,
        otherwise ``"<name> @ <branch>"``.
    """
    name = str(name or "")
    branch = str(branch or "").strip()
    if not branch:
        return name
    if name.lower().endswith((f"@ {branch}".lower(), f"({branch})".lower())):
        return name
    return f"{name} @ {branch}"


def run_branch(summary: Any, output: Any, options: Any = None) -> str:
    """Branch a run scanned, from what the run stored.

    Args:
        summary: ``TrivyRun.summary`` (``branch`` from this feature on).
        output: ``TrivyRun.output`` (engine ``metadata.Branch`` for HTTPS).
        options: ``TrivyRun.options`` (the requested ``branch``), used for
            runs that have not finished yet.

    Returns:
        The branch name, or "" when the run did not record one.
    """
    for value in (
        (summary or {}).get("branch") if isinstance(summary, dict) else None,
        ((output or {}).get("metadata") or {}).get("Branch")
        if isinstance(output, dict) and isinstance(output.get("metadata"), dict)
        else None,
        (options or {}).get("branch") if isinstance(options, dict) else None,
    ):
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""
