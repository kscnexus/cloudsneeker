"""Trivy Hub orchestration.

IaC and Image modes enqueue the existing ``scan-perform`` path.
Filesystem, repository, SBOM, and Kubernetes modes shell out to the Trivy
CLI and import JSON into shared Scan / Finding rows. Static analysis (SAST)
mode runs OpenGrep (:mod:`cloudsneeker_api.services.sast`) and imports the
same way.
"""

from __future__ import annotations

import base64
import binascii
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import yaml
from api.db_utils import rls_transaction
from api.models import Provider, Scan, StateChoices
from cloudsneeker.git_auth import (
    authenticated_clone_url,
    git_host_kind,
    redact,
    strip_userinfo,
)
from cloudsneeker.git_ssh import GitSshError, is_ssh_url, ssh_secret_args
from cloudsneeker.git_ssh import clone as git_clone
from cloudsneeker_api.appsec import capabilities as appsec_caps
from cloudsneeker_api.appsec.options import OptionError, validate_options
from cloudsneeker_api.models import TrivyRun, TrivyTarget
from cloudsneeker_api.services.vuln_db import scan_cache_env
from django.db import transaction
from django.utils import timezone

TRIVY_MODES = frozenset(
    {
        TrivyTarget.Mode.IAC,
        TrivyTarget.Mode.IMAGE,
        TrivyTarget.Mode.FS,
        TrivyTarget.Mode.REPO,
        TrivyTarget.Mode.SBOM,
        TrivyTarget.Mode.K8S,
        TrivyTarget.Mode.SAST,
        TrivyTarget.Mode.ROOTFS,
    }
)

# Modes that take an uploaded archive.
ARCHIVE_MODES = frozenset({TrivyTarget.Mode.FS, TrivyTarget.Mode.ROOTFS})

PROWLER_SCAN_MODES = frozenset({TrivyTarget.Mode.IAC, TrivyTarget.Mode.IMAGE})

MODE_PROVIDER_TYPES: dict[str, frozenset[str]] = {
    TrivyTarget.Mode.IAC: frozenset({Provider.ProviderChoices.IAC.value}),
    TrivyTarget.Mode.IMAGE: frozenset({Provider.ProviderChoices.IMAGE.value}),
    TrivyTarget.Mode.K8S: frozenset({Provider.ProviderChoices.KUBERNETES.value}),
    # CLI-imported scans become their provider's latest scan (Overview, Findings,
    # Resources), so they attach to a repository (IaC) provider, never a cloud
    # account whose real scan they would hide.
    TrivyTarget.Mode.FS: frozenset({Provider.ProviderChoices.IAC.value}),
    TrivyTarget.Mode.REPO: frozenset({Provider.ProviderChoices.IAC.value}),
    TrivyTarget.Mode.SBOM: frozenset({Provider.ProviderChoices.IAC.value}),
    TrivyTarget.Mode.SAST: frozenset({Provider.ProviderChoices.IAC.value}),
    TrivyTarget.Mode.ROOTFS: frozenset({Provider.ProviderChoices.IAC.value}),
}

# Modes whose ``repository_url`` must be the linked provider's repository.
REPOSITORY_URL_MODES = frozenset({TrivyTarget.Mode.REPO, TrivyTarget.Mode.SAST})

DEFAULT_SCANNERS = ("vuln", "misconfig", "secret")

# Scanners each mode accepts, from the engine capability matrix
# (``appsec.capabilities``), which follows the engine's CLI reference.
MODE_SCANNERS: dict[str, tuple[str, ...]] = {
    mode: tuple(spec["scanners"]) for mode, spec in appsec_caps.TARGETS.items()
}

# Scanners a target runs when its config lists none and names no profile.
MODE_DEFAULT_SCANNERS: dict[str, tuple[str, ...]] = {
    **MODE_SCANNERS,
    TrivyTarget.Mode.IAC: DEFAULT_SCANNERS,
    TrivyTarget.Mode.IMAGE: DEFAULT_SCANNERS,
    TrivyTarget.Mode.SBOM: ("vuln",),
    TrivyTarget.Mode.K8S: DEFAULT_SCANNERS,
}
TRIVY_TIMEOUT_SECONDS = int(os.environ.get("TRIVY_HUB_TIMEOUT_SECONDS", "900"))
MAX_ARCHIVE_BYTES = int(
    os.environ.get("TRIVY_HUB_MAX_ARCHIVE_BYTES", str(50 * 1024 * 1024))
)
MAX_SBOM_CHARS = int(os.environ.get("TRIVY_HUB_MAX_SBOM_CHARS", str(5 * 1024 * 1024)))


PROVIDER_SCAN_PATH = "provider_scan"

SCAN_STATE_TO_RUN_STATUS: dict[str, str] = {
    StateChoices.AVAILABLE.value: TrivyRun.Status.PENDING,
    StateChoices.SCHEDULED.value: TrivyRun.Status.PENDING,
    StateChoices.EXECUTING.value: TrivyRun.Status.RUNNING,
    StateChoices.COMPLETED.value: TrivyRun.Status.COMPLETED,
    StateChoices.FAILED.value: TrivyRun.Status.FAILED,
    StateChoices.CANCELLED.value: TrivyRun.Status.FAILED,
}


class TrivyHubError(ValueError):
    """Raised when a Trivy Hub target or run is invalid."""


def effective_run_status(
    run_status: str, summary: dict | None, scan_state: str | None
) -> str:
    """Return the status a run should report to users.

    IaC and image runs finish as soon as they hand off to ``scan-perform``,
    so their real outcome is the linked scan's state.

    Args:
        run_status: Stored ``TrivyRun.status``.
        summary: Stored ``TrivyRun.summary``.
        scan_state: State of the linked ``Scan``, if any.

    Returns:
        The run status to expose.
    """
    if run_status != TrivyRun.Status.COMPLETED or not scan_state:
        return run_status
    if (summary or {}).get("path") != PROVIDER_SCAN_PATH:
        return run_status
    return SCAN_STATE_TO_RUN_STATUS.get(scan_state, run_status)


@dataclass
class TrivyProcessBundle:
    """Temp files and env for one Trivy CLI invocation."""

    work_dir: Path
    env: dict[str, str] = field(default_factory=dict)
    cleanup_paths: list[Path] = field(default_factory=list)

    def close(self) -> None:
        for path in self.cleanup_paths:
            try:
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink(missing_ok=True)
            except OSError:
                pass
        shutil.rmtree(self.work_dir, ignore_errors=True)


def is_valid_trivy_mode(mode: str) -> bool:
    """Return True when mode is a supported Trivy Hub mode."""
    return mode in TRIVY_MODES


def normalize_repository_url(url: str) -> str:
    """Return a comparable form of a repository URL.

    Drops userinfo, a trailing ``/`` and ``.git``, and lower-cases the scheme
    and host. The path keeps its case.

    Args:
        url: Repository URL.

    Returns:
        The normalized URL.
    """
    value = strip_userinfo(str(url or "").strip())
    try:
        parts = urlsplit(value)
    except ValueError:
        return value.rstrip("/")
    path = parts.path.rstrip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    path = path.rstrip("/")
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{path}"


def _has_embedded_credentials(url: str) -> bool:
    """Return True when ``url`` carries a user name or password.

    The ``<org>@dev.azure.com/<org>/...`` form Azure DevOps puts in clone URLs
    is not a credential and is allowed, and so is the login name of an SSH URL
    (``ssh://git@host/...``): SSH authenticates with the provider's key.
    """
    if is_ssh_url(url):
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if "@" not in parts.netloc:
        return False
    if parts.password is not None or not parts.username:
        return True
    if git_host_kind(parts.hostname or "") == "azure_devops":
        first_segment = parts.path.lstrip("/").split("/", 1)[0]
        return parts.username.lower() != first_segment.lower()
    return True


def assert_provider_matches_mode(
    provider: Provider, mode: str, config: dict[str, Any] | None = None
) -> None:
    """Ensure the linked provider is allowed for the target mode and config.

    Args:
        provider: Linked provider.
        mode: Trivy Hub mode.
        config: Validated target config. In repo and sast modes its
            ``repository_url`` must be the provider's repository, so a target
            cannot send the provider's token to another URL.

    Raises:
        TrivyHubError: When the provider type or repository does not match.
    """
    allowed = MODE_PROVIDER_TYPES.get(mode)
    if allowed is None:
        raise TrivyHubError(f"Unknown Trivy mode: {mode}")
    if allowed and provider.provider not in allowed:
        raise TrivyHubError(
            f"Mode '{mode}' requires provider type "
            f"{', '.join(sorted(allowed))}; got '{provider.provider}'."
        )
    if mode in REPOSITORY_URL_MODES and config and config.get("repository_url"):
        target_url = normalize_repository_url(config["repository_url"])
        if target_url != normalize_repository_url(provider.uid or ""):
            raise TrivyHubError(
                "config.repository_url must match the linked IaC provider's "
                "repository URL."
            )


def normalize_scanners(mode: str, scanners: Any, *, strict: bool = True) -> list[str]:
    """Return the Trivy scanners a target of ``mode`` runs.

    Args:
        mode: Trivy Hub mode.
        scanners: ``config.scanners`` as stored or sent by the client.
        strict: Reject scanners the mode does not support. When False (runs
            of targets saved before the per-mode lists), drop them instead.

    Returns:
        Deduplicated scanner names in :data:`MODE_SCANNERS` order; the mode
        default when none are listed. Empty for SAST, which has no scanners.

    Raises:
        TrivyHubError: When ``scanners`` is malformed, empty or, in strict
            mode, lists a scanner the mode does not support.
    """
    allowed = MODE_SCANNERS.get(mode)
    if allowed is None:
        return []
    if scanners is None:
        return list(MODE_DEFAULT_SCANNERS[mode])
    if not isinstance(scanners, list) or not all(
        isinstance(item, str) and item.strip() for item in scanners
    ):
        raise TrivyHubError("config.scanners must be a list of scanner names.")
    requested = {item.strip().lower() for item in scanners}
    unsupported = sorted(requested - set(allowed))
    if unsupported and strict:
        raise TrivyHubError(
            f"Mode '{mode}' does not support scanner(s): {', '.join(unsupported)}. "
            f"Choose from: {', '.join(allowed)}."
        )
    selected = [name for name in allowed if name in requested]
    if not selected:
        if strict:
            raise TrivyHubError("config.scanners must list at least one scanner.")
        return list(MODE_DEFAULT_SCANNERS[mode])
    return selected


def validate_target_config(
    mode: str, config: dict[str, Any] | None, *, strict: bool = True
) -> dict[str, Any]:
    """Validate and normalize target config for a mode.

    Args:
        mode: Trivy Hub mode.
        config: Raw config JSON from the client.
        strict: See :func:`normalize_scanners`; runs pass False so targets
            saved before scanner validation keep running.

    Returns:
        Normalized config mapping.

    Raises:
        TrivyHubError: When required fields are missing or invalid.
    """
    if not is_valid_trivy_mode(mode):
        raise TrivyHubError(f"Unknown Trivy mode: {mode}")
    cfg = dict(config or {})

    cfg["scanners"] = normalize_scanners(mode, cfg.get("scanners"), strict=strict)
    _validate_profile_and_options(mode, cfg, strict=strict)

    if mode == TrivyTarget.Mode.IMAGE:
        images = cfg.get("images") or cfg.get("image")
        if isinstance(images, str):
            images = [images]
        if images is not None and (
            not isinstance(images, list)
            or not all(isinstance(item, str) and item.strip() for item in images)
        ):
            raise TrivyHubError("config.images must be a list of image references.")
        if isinstance(images, list):
            cfg["images"] = [item.strip() for item in images]

    if mode == TrivyTarget.Mode.REPO:
        url = str(cfg.get("repository_url") or cfg.get("url") or "").strip()
        if not url:
            raise TrivyHubError("config.repository_url is required for repo mode.")
        if _has_embedded_credentials(url):
            raise TrivyHubError(
                "config.repository_url must not contain credentials. Save the "
                "access token (and username) on the IaC provider instead."
            )
        cfg["repository_url"] = url

    if mode in ARCHIVE_MODES:
        # Scanning a worker path would let a tenant read the worker's disk;
        # only an uploaded archive is scanned.
        if str(cfg.get("path") or "").strip():
            raise TrivyHubError(
                "config.path is not supported; upload an archive "
                "(config.archive_b64) instead."
            )
        cfg.pop("path", None)
        archive = str(cfg.get("archive_b64") or "")
        if not archive:
            raise TrivyHubError(f"config.archive_b64 is required for {mode} mode.")
        # Rough decoded size check without full decode for huge strings.
        if len(archive) > MAX_ARCHIVE_BYTES * 2:
            raise TrivyHubError("Filesystem archive exceeds the size limit.")
        assert_supported_archive(archive)

    if mode == TrivyTarget.Mode.SBOM:
        sbom = cfg.get("sbom")
        if not isinstance(sbom, str) or not sbom.strip():
            raise TrivyHubError("config.sbom is required for sbom mode.")
        if len(sbom) > MAX_SBOM_CHARS:
            raise TrivyHubError("SBOM payload exceeds the size limit.")
        cfg["sbom"] = sbom

    if mode == TrivyTarget.Mode.K8S:
        # Cluster identity comes from the linked kubernetes provider.
        pass

    if mode == TrivyTarget.Mode.SAST:
        from cloudsneeker_api.services.sast import validate_sast_config

        cfg = validate_sast_config(cfg)

    return cfg


def _validate_profile_and_options(
    mode: str, cfg: dict[str, Any], *, strict: bool
) -> None:
    """Validate ``config.profile`` and ``config.options`` in place.

    ``profile`` is ``builtin:<key>`` or a scan profile id (its existence is
    checked when the scan starts). ``options`` are engine options for the
    mode; with ``strict`` off, unsupported ones are dropped.

    Raises:
        TrivyHubError: Malformed profile reference or invalid options.
    """
    profile = cfg.get("profile")
    if profile in (None, ""):
        cfg.pop("profile", None)
    else:
        ref = str(profile).strip()
        prefix = appsec_caps.BUILTIN_PROFILE_PREFIX
        if ref.startswith(prefix):
            if ref[len(prefix) :] not in appsec_caps.BUILTIN_PROFILES:
                raise TrivyHubError(f"Unknown scan profile: {ref}.")
        else:
            try:
                UUID(ref)
            except ValueError:
                raise TrivyHubError("config.profile is not a profile id.") from None
        cfg["profile"] = ref

    options = cfg.get("options")
    if options in (None, {}):
        cfg.pop("options", None)
        return
    if mode not in appsec_caps.TARGETS:
        raise TrivyHubError(f"Mode '{mode}' takes no scan options.")
    if not isinstance(options, dict):
        raise TrivyHubError("config.options must be an object.")
    try:
        cleaned = validate_options(
            mode,
            {"scanners": cfg.get("scanners"), **options},
            strict=strict,
        )
    except OptionError as exc:
        raise TrivyHubError(str(exc)) from None
    if "scanners" not in options:
        cleaned.pop("scanners", None)
    cfg["options"] = cleaned


def _resolve_trivy_bin() -> str:
    configured = os.environ.get("TRIVY_BIN", "").strip()
    if configured:
        return configured
    found = shutil.which("trivy")
    if not found:
        raise TrivyHubError("Trivy binary was not found on the worker.")
    return found


def _scanners_args(config: dict[str, Any]) -> list[str]:
    scanners = config.get("scanners") or list(DEFAULT_SCANNERS)
    return ["--scanners", ",".join(scanners)]


def _severity_args(config: dict[str, Any]) -> list[str]:
    severities = config.get("severity") or config.get("severities")
    if not severities:
        return []
    if isinstance(severities, list):
        value = ",".join(str(item) for item in severities)
    else:
        value = str(severities)
    return ["--severity", value]


ARCHIVE_FORMAT_HELP = (
    "Upload a ZIP or TAR archive (.zip, .tar, .tar.gz, .tgz, .tar.bz2, .tar.xz)."
)


def _archive_head(archive_b64: str, size: int = 512) -> bytes:
    """Decode only the first ``size`` bytes of a base64 archive."""
    chunk = "".join(archive_b64[: (size // 3 + 1) * 4].split())
    chunk = chunk[: len(chunk) - len(chunk) % 4]
    try:
        return base64.b64decode(chunk, validate=False)[:size]
    except (binascii.Error, ValueError):
        return b""


def assert_supported_archive(archive_b64: str) -> None:
    """Reject archives the scanners cannot unpack before the target is saved.

    Raises:
        TrivyHubError: When the upload is not a ZIP, TAR or compressed TAR.
    """
    head = _archive_head(archive_b64)
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        raise TrivyHubError(f"7-Zip archives are not supported. {ARCHIVE_FORMAT_HELP}")
    if head.startswith(b"Rar!"):
        raise TrivyHubError(f"RAR archives are not supported. {ARCHIVE_FORMAT_HELP}")
    supported = (
        head.startswith((b"PK\x03\x04", b"PK\x05\x06"))  # zip
        or head.startswith(b"\x1f\x8b")  # gzip (.tar.gz)
        or head.startswith(b"BZh")  # bzip2 (.tar.bz2)
        or head.startswith(b"\xfd7zXZ\x00")  # xz (.tar.xz)
        or head[257:262] == b"ustar"  # tar
    )
    if not supported:
        raise TrivyHubError(
            f"The file is not a ZIP or TAR archive. {ARCHIVE_FORMAT_HELP}"
        )


def _extract_archive(archive_b64: str, dest: Path) -> Path:
    raw = base64.b64decode(archive_b64, validate=False)
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise TrivyHubError("Filesystem archive exceeds the size limit.")
    archive_path = dest / "upload.bin"
    archive_path.write_bytes(raw)
    extract_dir = dest / "fs-root"
    extract_dir.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(extract_dir)
    else:
        try:
            with tarfile.open(archive_path, mode="r:*") as tf:
                tf.extractall(extract_dir)
        except tarfile.TarError as exc:
            raise TrivyHubError(
                f"The file is not a ZIP or TAR archive. {ARCHIVE_FORMAT_HELP}"
            ) from exc
    return extract_dir


def _kubeconfig_env(provider: Provider, work_dir: Path) -> dict[str, str]:
    secret = provider.secret.secret if getattr(provider, "secret", None) else {}
    content = secret.get("kubeconfig_content")
    if not content:
        raise TrivyHubError("Kubernetes provider requires kubeconfig_content.")
    kubeconfig_path = work_dir / "kubeconfig"
    if isinstance(content, dict):
        kubeconfig_path.write_text(yaml.safe_dump(content), encoding="utf-8")
    else:
        kubeconfig_path.write_text(str(content), encoding="utf-8")
    return {"KUBECONFIG": str(kubeconfig_path)}


def _repo_credentials(provider: Provider) -> tuple[str, str | None]:
    """Return ``(token, username)`` from the linked IaC provider secret."""
    secret = {}
    if getattr(provider, "secret", None) is not None:
        secret = provider.secret.secret or {}
    token = (
        secret.get("access_token")
        or secret.get("personal_access_token")
        or secret.get("oauth_app_token")
        or ""
    )
    username = secret.get("username") or secret.get("github_username") or None
    return str(token), (str(username) if username else None)


def repo_ssh_args(provider: Provider) -> tuple[str | None, str | None, str | None]:
    """Return ``(private_key, known_hosts, passphrase)`` from the provider secret."""
    secret = {}
    if getattr(provider, "secret", None) is not None:
        secret = provider.secret.secret or {}
    return ssh_secret_args(secret)


def clone_ssh_repository(repository_url: str, provider: Provider, dest: Path) -> Path:
    """Clone an SSH repository URL with the provider's key into ``dest``.

    ``trivy repo`` cannot authenticate over SSH, so SSH repositories are
    cloned here and scanned with ``trivy fs``. ``.git`` is removed afterwards.

    Args:
        repository_url: ``git@host:owner/repo`` or ``ssh://`` URL.
        provider: Linked IaC provider holding ``ssh_private_key``.
        dest: Directory to clone into (created if missing).

    Returns:
        ``dest``.

    Raises:
        TrivyHubError: The key is missing or unreadable, or the clone failed.
    """
    dest.mkdir(parents=True, exist_ok=True)
    try:
        git_clone(
            repository_url,
            str(dest),
            *repo_ssh_args(provider),
            depth=1,
            errstream=io.BytesIO(),
        )
    except GitSshError as error:
        raise TrivyHubError(f"Repository clone failed: {error}") from None
    shutil.rmtree(dest / ".git", ignore_errors=True)
    return dest


def _repo_token_env(provider: Provider) -> dict[str, str]:
    token, _username = _repo_credentials(provider)
    if not token:
        return {}
    return {
        "GITHUB_TOKEN": token,
        "GITLAB_TOKEN": token,
    }


def repo_scan_target(
    repository_url: str, provider: Provider
) -> tuple[str, dict[str, str], tuple[str, ...]]:
    """Return the URL, env, and secrets for ``trivy repo``.

    GitHub and GitLab hosts keep Trivy's ``GITHUB_TOKEN`` / ``GITLAB_TOKEN``
    env. Bitbucket, Azure DevOps, and other hosts get the token in the URL
    userinfo, built by :func:`cloudsneeker.git_auth.authenticated_clone_url`.

    Args:
        repository_url: Repository URL from the target config.
        provider: Linked IaC provider.

    Returns:
        ``(url, env, secrets)``; ``secrets`` must be redacted from any output.
    """
    token, username = _repo_credentials(provider)
    if not token:
        return repository_url, {}, ()
    host = urlsplit(repository_url).hostname or ""
    if git_host_kind(host) in ("github", "gitlab"):
        return repository_url, _repo_token_env(provider), (token,)
    auth_url = authenticated_clone_url(repository_url, token, username)
    return auth_url, {}, (auth_url, token)


def scrub_secrets(value: Any, secrets: tuple[str, ...]) -> Any:
    """Return ``value`` with every secret string replaced by ``***``.

    Args:
        value: Parsed JSON (dict, list, str, ...) or text.
        secrets: Tokens or authenticated URLs.

    Returns:
        The scrubbed value, same shape as ``value``.
    """
    if not secrets:
        return value
    if isinstance(value, str):
        return redact(value, *secrets)
    if isinstance(value, dict):
        return {
            scrub_secrets(key, secrets): scrub_secrets(item, secrets)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [scrub_secrets(item, secrets) for item in value]
    return value


def command_secrets(
    mode: str, config: dict[str, Any], provider: Provider
) -> tuple[str, ...]:
    """Return the secrets a mode's Trivy invocation carries.

    Args:
        mode: Trivy Hub mode.
        config: Validated target config.
        provider: Linked provider.

    Returns:
        Tokens and authenticated URLs to redact (empty outside repo mode).
    """
    if mode != TrivyTarget.Mode.REPO or not config.get("repository_url"):
        return ()
    return repo_scan_target(str(config["repository_url"]), provider)[2]


def build_trivy_command(
    *,
    mode: str,
    config: dict[str, Any],
    provider: Provider,
    work_dir: Path,
) -> tuple[list[str], dict[str, str]]:
    """Build argv and env for a direct Trivy CLI mode (not iac/image).

    Args:
        mode: Direct CLI mode (fs, repo, sbom, k8s).
        config: Validated target config.
        provider: Linked provider.
        work_dir: Temporary directory for uploaded or generated files.

    Returns:
        ``(argv, env)``. In repo mode ``argv`` may carry an authenticated URL;
        :func:`command_secrets` lists what to redact from any output.
    """
    binary = _resolve_trivy_bin()
    env = {**os.environ, **scan_cache_env(work_dir)}
    common = [
        binary,
        "--quiet",
        "-f",
        "json",
        *_scanners_args(config),
        *_severity_args(config),
    ]

    if mode == TrivyTarget.Mode.FS:
        if not config.get("archive_b64"):
            raise TrivyHubError("config.archive_b64 is required for fs mode.")
        scan_path = _extract_archive(str(config["archive_b64"]), work_dir)
        return [*common, "fs", str(scan_path)], env

    if mode == TrivyTarget.Mode.REPO:
        if is_ssh_url(str(config["repository_url"])):
            clone_dir = clone_ssh_repository(
                str(config["repository_url"]), provider, work_dir / "repository"
            )
            return [*common, "fs", str(clone_dir)], env
        url, repo_env, _secrets = repo_scan_target(
            str(config["repository_url"]), provider
        )
        env.update(repo_env)
        return [*common, "repo", url], env

    if mode == TrivyTarget.Mode.SBOM:
        sbom_path = work_dir / "sbom.json"
        sbom_path.write_text(str(config["sbom"]), encoding="utf-8")
        return [*common, "sbom", str(sbom_path)], env

    if mode == TrivyTarget.Mode.K8S:
        env.update(_kubeconfig_env(provider, work_dir))
        context = str(config.get("context") or provider.uid or "").strip()
        namespace = str(config.get("namespace") or "").strip()
        args = [*common, "k8s"]
        if context:
            args.extend(["--context", context])
        if namespace:
            args.extend(["--include-namespaces", namespace])
        args.append("cluster")
        return args, env

    raise TrivyHubError(f"Mode '{mode}' is not a direct Trivy CLI mode.")


def run_trivy_cli(
    *,
    mode: str,
    config: dict[str, Any],
    provider: Provider,
) -> dict[str, Any]:
    """Execute Trivy and return parsed JSON with provider secrets redacted.

    Args:
        mode: Direct CLI mode.
        config: Validated target config.
        provider: Linked provider.

    Returns:
        The Trivy JSON report.

    Raises:
        TrivyHubError: When Trivy fails; the message never carries a token.
    """
    work_dir = Path(tempfile.mkdtemp(prefix="cloudsneeker-trivy-"))
    bundle = TrivyProcessBundle(work_dir=work_dir)
    secrets = command_secrets(mode, config, provider)
    try:
        argv, env = build_trivy_command(
            mode=mode, config=config, provider=provider, work_dir=work_dir
        )
        process = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            env=env,
            timeout=TRIVY_TIMEOUT_SECONDS,
            check=False,
        )
        # Trivy exits non-zero when vulnerabilities are found; still parse stdout.
        stdout = process.stdout or ""
        if not stdout.strip():
            stderr = redact((process.stderr or "").strip(), *secrets)
            raise TrivyHubError(
                stderr or f"Trivy produced no JSON output (exit {process.returncode})."
            )
        try:
            report = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise TrivyHubError(
                f"Trivy returned invalid JSON: {redact(str(exc), *secrets)}"
            ) from None
        if not isinstance(report, dict):
            raise TrivyHubError("Trivy JSON root must be an object.")
        return scrub_secrets(report, secrets)
    except subprocess.TimeoutExpired:
        # TimeoutExpired carries argv, which may hold an authenticated URL.
        raise TrivyHubError("Trivy scan timed out.") from None
    except TrivyHubError:
        raise
    except Exception as exc:  # noqa: BLE001 - never surface a token in errors
        if not secrets:
            raise
        raise TrivyHubError(
            f"Trivy could not run: {redact(str(exc), *secrets)}"
        ) from None
    finally:
        bundle.close()


def _enqueue_provider_scan(
    *,
    tenant_id: str,
    provider: Provider,
    run: TrivyRun,
    scan_name: str,
) -> Scan:
    """Create a Scan and enqueue existing scan-perform for iac/image."""
    from tasks.tasks import create_scan_task_record, enqueue_scan_execution_on_commit

    task_id = str(uuid4())
    scan = Scan.objects.create(
        tenant_id=tenant_id,
        provider=provider,
        name=scan_name[:100],
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.AVAILABLE,
        scanner_args={"source": "trivy_hub", "mode": run.target.mode},
        task_id=task_id,
    )
    create_scan_task_record(
        tenant_id=tenant_id,
        task_id=task_id,
        task_kwargs={
            "tenant_id": str(tenant_id),
            "scan_id": str(scan.id),
            "provider_id": str(provider.id),
        },
    )
    enqueue_scan_execution_on_commit(tenant_id=tenant_id, scan=scan, task_id=task_id)
    return scan


def enqueue_trivy_run(
    *,
    tenant_id: str,
    target_id: str,
    trigger: str = TrivyRun.Trigger.MANUAL,
    triggered_by_id: str | None = None,
) -> TrivyRun:
    """Create a pending Trivy run and enqueue the worker after commit."""
    from cloudsneeker_api.tasks import trivy_scan_task

    if trigger not in {TrivyRun.Trigger.MANUAL, TrivyRun.Trigger.SCHEDULED}:
        raise TrivyHubError(f"Unknown Trivy run trigger: {trigger}")

    with rls_transaction(tenant_id):
        target = TrivyTarget.objects.select_related("provider").get(
            tenant_id=tenant_id, id=target_id
        )
        config = validate_target_config(target.mode, target.config, strict=False)
        assert_provider_matches_mode(target.provider, target.mode, config)
        active = TrivyRun.objects.filter(
            tenant_id=tenant_id,
            target_id=target_id,
            status__in=[TrivyRun.Status.PENDING, TrivyRun.Status.RUNNING],
        ).count()
        max_concurrent = int(os.environ.get("TRIVY_HUB_MAX_CONCURRENT_PER_TARGET", "2"))
        if active >= max_concurrent:
            raise TrivyHubError(
                f"Target already has {active} active run(s); limit is {max_concurrent}."
            )
        tenant_limit = int(os.environ.get("APPSEC_MAX_ACTIVE_RUNS_PER_TENANT", "10"))
        tenant_active = TrivyRun.objects.filter(
            tenant_id=tenant_id,
            status__in=[TrivyRun.Status.PENDING, TrivyRun.Status.RUNNING],
        ).count()
        if tenant_active >= tenant_limit:
            raise TrivyHubError(
                f"{tenant_active} scans are already queued or running; the "
                f"limit is {tenant_limit}. Wait for one to finish."
            )
        run = TrivyRun.objects.create(
            tenant_id=tenant_id,
            target=target,
            provider=target.provider,
            status=TrivyRun.Status.PENDING,
            trigger=trigger,
            triggered_by_id=triggered_by_id,
        )

    run_id = str(run.id)
    transaction.on_commit(
        lambda: trivy_scan_task.delay(tenant_id=tenant_id, run_id=run_id)
    )
    return run


def request_run_cancel(*, tenant_id: str, run_id: str) -> TrivyRun:
    """Ask a pending or running scan to stop.

    A pending run is cancelled at once. A running one is flagged; the worker
    polls the flag, stops the scan process and marks the run cancelled.

    Raises:
        TrivyHubError: The run is unknown or already finished.
    """
    with rls_transaction(tenant_id):
        run = (
            TrivyRun.objects.select_for_update()
            .filter(tenant_id=tenant_id, id=run_id)
            .first()
        )
        if run is None:
            raise TrivyHubError("Scan not found.")
        if run.status not in (TrivyRun.Status.PENDING, TrivyRun.Status.RUNNING):
            raise TrivyHubError("Only a queued or running scan can be cancelled.")
        now = timezone.now()
        run.cancel_requested_at = now
        fields = ["cancel_requested_at", "updated_at"]
        if run.status == TrivyRun.Status.PENDING:
            run.status = TrivyRun.Status.CANCELLED
            run.finished_at = now
            run.error = "The scan was cancelled before it started."
            run.error_class = "cancelled"
            fields += ["status", "finished_at", "error", "error_class"]
        run.save(update_fields=fields)
    return run


def process_trivy_run(*, tenant_id: str, run_id: str) -> dict[str, str]:
    """Execute a pending scan run (``appsec.engine``)."""
    from cloudsneeker_api.appsec.engine import execute_run

    return execute_run(tenant_id=tenant_id, run_id=run_id)

