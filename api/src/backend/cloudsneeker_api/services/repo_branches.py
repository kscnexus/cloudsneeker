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


# ``TrivyTarget.name`` max length.
TARGET_NAME_MAX = 100


def strip_branch(name: str, branch: str | None) -> str:
    """``name`` without a trailing ``" @ <branch>"`` or ``" (<branch>)"``."""
    name = str(name or "")
    branch = str(branch or "").strip()
    if not branch:
        return name
    for suffix in (f" @ {branch}", f" ({branch})"):
        if name.lower().endswith(suffix.lower()):
            return name[: -len(suffix)].rstrip()
    return name


def name_for_branch(name: str, branch: str | None, previous: str | None = "") -> str:
    """Target name that carries the branch it scans.

    The branch is part of the name, so every list, report, export and scan
    name that shows a target shows its branch too.

    Args:
        name: Current or requested target name.
        branch: Branch the target scans ("" for none).
        previous: Branch the target scanned before, removed from the name.

    Returns:
        ``"<base> @ <branch>"`` within ``TARGET_NAME_MAX`` characters, or the
        base name when there is no branch.
    """
    branch = str(branch or "").strip()
    base = strip_branch(strip_branch(name, previous), branch) or str(name or "")
    if not branch:
        return base[:TARGET_NAME_MAX]
    suffix = f" @ {branch}"
    room = TARGET_NAME_MAX - len(suffix)
    if room < 3:
        return base[:TARGET_NAME_MAX]
    return f"{base[:room].rstrip()}{suffix}"


def pin_target_branch(target: Any, branch: str, *, using: str | None = None) -> bool:
    """Record the branch a Git target scans and put it in the target's name.

    Used for targets saved without a branch (the repository's default
    branch): after a scan, or by :func:`backfill_target_branches`. A target
    that already has a branch, or reads no repository URL, is left alone. The
    name keeps its old value when the new one is taken by another target.

    Args:
        target: ``TrivyTarget``.
        branch: Branch the target scans.
        using: Database alias (the engine writes on the admin alias).

    Returns:
        True when the target was updated.
    """
    from cloudsneeker_api.models import TrivyTarget
    from django.utils import timezone

    config = dict(target.config or {})
    try:
        branch = normalize_branch(branch)
    except ValueError:
        return False
    if not branch or config.get("branch") or not config.get("repository_url"):
        return False
    if target.mode not in ("repo", "sast"):
        return False
    config["branch"] = branch
    manager = TrivyTarget.objects.using(using) if using else TrivyTarget.objects
    name = name_for_branch(target.name, branch)
    if (
        name != target.name
        and manager.filter(tenant_id=target.tenant_id, name=name)
        .exclude(pk=target.pk)
        .exists()
    ):
        name = target.name
    manager.filter(pk=target.pk).update(
        config=config, name=name, updated_at=timezone.now()
    )
    target.config, target.name = config, name
    return True


def backfill_target_branches(tenant_id: str) -> dict[str, int]:
    """Record the branch of every Git target saved without one.

    The branch is the one the target's latest completed run recorded, else
    the repository's current default branch (listed once per source).

    Args:
        tenant_id: Tenant UUID string.

    Returns:
        Counts: ``updated``, ``unchanged`` (branch already set or no
        repository URL) and ``failed`` (repository could not be read).
    """
    from api.db_utils import rls_transaction
    from cloudsneeker_api.models import TrivyRun, TrivyTarget

    with rls_transaction(tenant_id):
        targets = list(
            TrivyTarget.objects.filter(tenant_id=tenant_id, mode__in=("repo", "sast"))
            .select_related("provider", "provider__secret")
            .order_by("name")
        )
        recorded: dict[str, str] = {}
        for row in (
            TrivyRun.objects.filter(
                tenant_id=tenant_id,
                target_id__in=[target.id for target in targets],
                status=TrivyRun.Status.COMPLETED,
            )
            .order_by("target_id", "-finished_at")
            .values("target_id", "summary", "output", "options")
        ):
            key = str(row["target_id"])
            if key not in recorded:
                recorded[key] = run_branch(row["summary"], row["output"], None)

    counts = {"updated": 0, "unchanged": 0, "failed": 0}
    defaults: dict[str, str | None] = {}
    for target in targets:
        config = target.config or {}
        if config.get("branch") or not config.get("repository_url"):
            counts["unchanged"] += 1
            continue
        branch = recorded.get(str(target.id), "")
        if not branch:
            key = str(target.provider_id)
            if key not in defaults:
                try:
                    defaults[key] = list_repository_branches(
                        str(config["repository_url"]), target.provider
                    ).default_branch
                except RepositoryBranchError:
                    defaults[key] = None
            branch = defaults[key] or ""
        if not branch:
            counts["failed"] += 1
            continue
        with rls_transaction(tenant_id):
            updated = pin_target_branch(target, branch)
        counts["updated" if updated else "unchanged"] += 1
    return counts
