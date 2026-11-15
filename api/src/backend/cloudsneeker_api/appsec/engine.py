"""Scan execution: one ``TrivyRun`` from queue to stored results.

Flow: resolve options (profile, application, target) -> prepare the
workspace (clone, extract, write documents) -> write tenant policy files ->
run the engine as a child process (argument list, minimal environment,
separate stdout and stderr files, timeout, cancellation, bounded retry) ->
parse -> mask and store the raw report -> reconcile findings, store the
inventory and write the shared ``Scan`` / ``Finding`` rows in one
transaction -> record the outcome on the run.

Run state is written through the admin connection so it commits at once:
the Celery task itself runs inside one transaction, which would otherwise
hide ``running`` and block cancellation until the scan ended.
"""

from __future__ import annotations

import base64
import gzip
import json
import logging
import os
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cloudsneeker_api.appsec import capabilities as caps
from cloudsneeker_api.appsec import failures, parser, policies, sbom
from cloudsneeker_api.appsec.options import (
    OptionError,
    build_scan_args,
    engine_timeout_seconds,
    merge_options,
    validate_options,
)

logger = logging.getLogger(__name__)

ENGINE_OPENGREP = "opengrep"
ARTIFACT_DIRNAME = "cloudsneeker-appsec"
REPORT_FILE = "report-{index}.json.gz"
POLL_SECONDS = 2.0
PROVIDER_SCAN_PATH = "provider_scan"

# Environment variables the scan process may inherit. Everything else
# (database, broker and Django secrets) stays out of a process that reads
# untrusted repositories and images.
ENV_PASSTHROUGH = (
    "PATH",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "SYSTEMROOT",
    "XDG_CACHE_HOME",
)
ENV_PASSTHROUGH_PREFIXES = ("TRIVY_",)
ENV_NEVER = ("TRIVY_USERNAME", "TRIVY_PASSWORD", "TRIVY_REGISTRY_TOKEN")


class EngineError(Exception):
    """A scan could not run; carries a classified failure."""

    def __init__(self, failure: failures.Failure):
        super().__init__(failure.message)
        self.failure = failure


def _env_int(name: str, default: int, low: int = 0) -> int:
    try:
        return max(low, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def engine_limits() -> dict[str, int]:
    """Platform limits, read from the environment (not tenant editable)."""
    return {
        "default_timeout_seconds": _env_int("TRIVY_HUB_TIMEOUT_SECONDS", 900, 60),
        "max_active_runs_per_target": _env_int(
            "TRIVY_HUB_MAX_CONCURRENT_PER_TARGET", 2, 1
        ),
        "max_active_runs_per_tenant": _env_int(
            "APPSEC_MAX_ACTIVE_RUNS_PER_TENANT", 10, 1
        ),
        "max_queued_runs_per_tenant": _env_int(
            "APPSEC_MAX_QUEUED_RUNS_PER_TENANT", 1000, 1
        ),
        "max_attempts": _env_int("APPSEC_ENGINE_MAX_ATTEMPTS", 3, 1),
        "max_report_bytes": _env_int(
            "APPSEC_MAX_REPORT_BYTES", 512 * 1024 * 1024, 1024
        ),
        "max_archive_bytes": _env_int(
            "TRIVY_HUB_MAX_ARCHIVE_BYTES", 50 * 1024 * 1024, 1024
        ),
        "max_extracted_bytes": _env_int(
            "APPSEC_MAX_EXTRACTED_BYTES", 2 * 1024 * 1024 * 1024, 1024
        ),
        "max_extracted_files": _env_int("APPSEC_MAX_EXTRACTED_FILES", 200_000, 1),
        "max_images_per_run": _env_int("APPSEC_MAX_IMAGES_PER_RUN", 20, 1),
    }


def direct_modes() -> frozenset[str]:
    """Target types this engine runs itself.

    ``APPSEC_ENGINE_DIRECT_MODES`` (comma separated) narrows the set; a type
    left out falls back to the previous path where one exists. This is the
    rollback switch for the Infrastructure as Code and image types.
    """
    configured = os.environ.get("APPSEC_ENGINE_DIRECT_MODES", "").strip()
    if not configured:
        return frozenset(caps.TARGETS)
    return frozenset(
        item.strip() for item in configured.split(",") if item.strip()
    ) & frozenset(caps.TARGETS)


def artifact_root() -> Path:
    from django.conf import settings

    return Path(settings.DJANGO_TMP_OUTPUT_DIRECTORY) / ARTIFACT_DIRNAME


def run_artifact_dir(tenant_id: str, run_id: str) -> Path:
    return artifact_root() / str(tenant_id) / str(run_id)


def resolve_binary() -> str:
    configured = os.environ.get("TRIVY_BIN", "").strip()
    found = configured or shutil.which("trivy")
    if not found:
        raise EngineError(
            failures.failure(
                failures.FAILURE_ENGINE,
                "The scan engine is not installed on the worker.",
            )
        )
    return found


_VERSION_CACHE: dict[str, Any] = {}


def engine_status(*, refresh: bool = False) -> dict[str, Any]:
    """Installed engine version and the databases in its default cache.

    Returns:
        ``{"available", "version", "pinned_version", "matches_pin",
        "vulnerability_db", "java_db", "check_bundle", "error"}``.
    """
    if _VERSION_CACHE and not refresh and time.monotonic() - _VERSION_CACHE["at"] < 300:
        return _VERSION_CACHE["value"]
    value: dict[str, Any] = {
        "available": False,
        "version": "",
        "pinned_version": caps.ENGINE_VERSION,
        "matches_pin": False,
        "vulnerability_db": None,
        "java_db": None,
        "check_bundle": None,
        "error": "",
    }
    try:
        binary = resolve_binary()
        process = subprocess.run(
            [binary, "version", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            env=base_environment(),
        )
        data = json.loads(process.stdout or "{}")
        value.update(
            available=True,
            version=str(data.get("Version") or ""),
            vulnerability_db=data.get("VulnerabilityDB"),
            java_db=data.get("JavaDB"),
            check_bundle=data.get("CheckBundle"),
        )
        value["matches_pin"] = value["version"].lstrip("v") == caps.ENGINE_VERSION
    except EngineError as exc:
        value["error"] = str(exc)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        value["error"] = (
            f"The scan engine did not report its version: {type(exc).__name__}."
        )
    _VERSION_CACHE.update(at=time.monotonic(), value=value)
    return value


def base_environment() -> dict[str, str]:
    """Environment for the scan process, without platform secrets."""
    env = {}
    for name, value in os.environ.items():
        if name in ENV_NEVER:
            continue
        if name in ENV_PASSTHROUGH or name.startswith(ENV_PASSTHROUGH_PREFIXES):
            env[name] = value
    return env


# --- Workspace ----------------------------------------------------------------


def _inside(base: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def safe_extract(
    archive_b64: str, dest: Path, limits: dict[str, int] | None = None
) -> Path:
    """Extract an uploaded ZIP or TAR archive without leaving ``dest``.

    Rejects absolute paths, ``..`` segments, links and special files, and
    stops at the file-count and size limits (archive bombs).

    Args:
        archive_b64: Base64 archive.
        dest: Scan directory; files go to ``dest/fs-root``.
        limits: ``engine_limits()``.

    Returns:
        The extraction directory.

    Raises:
        EngineError: Unsupported, oversized or unsafe archive.
    """
    limits = limits or engine_limits()

    def bad(detail: str) -> EngineError:
        return EngineError(failures.failure(failures.FAILURE_INPUT, detail))

    try:
        raw = base64.b64decode(archive_b64, validate=False)
    except (ValueError, TypeError):
        raise bad("The archive is not valid base64.") from None
    if len(raw) > limits["max_archive_bytes"]:
        raise bad("The archive exceeds the upload size limit.")
    archive_path = dest / "upload.bin"
    archive_path.write_bytes(raw)
    root = dest / "fs-root"
    root.mkdir(parents=True, exist_ok=True)
    total = 0
    count = 0

    def account(size: int) -> None:
        nonlocal total, count
        total += max(0, size)
        count += 1
        if count > limits["max_extracted_files"]:
            raise bad("The archive holds too many files.")
        if total > limits["max_extracted_bytes"]:
            raise bad("The archive expands beyond the size limit.")

    try:
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path) as archive:
                for info in archive.infolist():
                    name = info.filename
                    if name.startswith(("/", "\\")) or ".." in Path(name).parts:
                        raise bad("The archive contains a path outside its root.")
                    if (info.external_attr >> 16) & 0o170000 == 0o120000:
                        continue  # symbolic link
                    target = root / name
                    if not _inside(root, target):
                        raise bad("The archive contains a path outside its root.")
                    account(info.file_size)
                    if info.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as source, open(target, "wb") as sink:
                        shutil.copyfileobj(source, sink, length=1024 * 1024)
        else:
            with tarfile.open(archive_path, mode="r:*") as archive:
                for member in archive:
                    if not (member.isfile() or member.isdir()):
                        continue  # links, devices, fifos
                    name = member.name
                    if name.startswith(("/", "\\")) or ".." in Path(name).parts:
                        raise bad("The archive contains a path outside its root.")
                    target = root / name
                    if not _inside(root, target):
                        raise bad("The archive contains a path outside its root.")
                    account(member.size)
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        continue
                    with source, open(target, "wb") as sink:
                        shutil.copyfileobj(source, sink, length=1024 * 1024)
    except (tarfile.TarError, zipfile.BadZipFile, OSError):
        raise bad("The file is not a readable ZIP or TAR archive.") from None
    finally:
        archive_path.unlink(missing_ok=True)
    return root


@dataclass
class ScanUnit:
    """One engine invocation of a run (a run of an image list has several)."""

    subcommand: str
    target_arg: str | None
    label: str
    scope: str = ""
    env: dict[str, str] = field(default_factory=dict)
    secrets: tuple[str, ...] = ()
    option_overrides: dict[str, Any] = field(default_factory=dict)
    sbom_format: str = ""
    # Git branch the unit reads; "" when unknown (the engine may report it).
    branch: str = ""


# Engine options that pick a Git reference; only one may be set.
REF_OPTIONS = ("branch", "tag", "commit")


def apply_target_branch(
    config: dict[str, Any], options: dict[str, Any]
) -> dict[str, Any]:
    """Options with the target's ``config.branch`` as the Git reference.

    A target's branch replaces any branch, tag or commit from its profile or
    options, so one target always scans the branch it was created for.

    Args:
        config: Validated target config.
        options: Resolved run options.

    Returns:
        ``options`` unchanged without a branch, else a copy with it set.
    """
    branch = str(config.get("branch") or "")
    if not branch:
        return options
    kept = {key: value for key, value in options.items() if key not in REF_OPTIONS}
    return {**kept, "branch": branch}


def image_scope(reference: str) -> str:
    """Image reference without tag or digest, stable across releases."""
    value = reference.split("@", 1)[0]
    last = value.rsplit("/", 1)[-1]
    if ":" in last:
        value = value[: value.rfind(":")]
    return value


def is_registry_wide(provider_uid: str, config: dict[str, Any]) -> bool:
    """True when an image target names a registry and lists no image."""
    if config.get("images"):
        return False
    from prowler.providers.image.image_provider import ImageProvider

    return ImageProvider._is_registry_url(provider_uid or "")


def _image_environment(provider) -> tuple[dict[str, str], tuple[str, ...]]:
    from cloudsneeker_api.ecr_auth import EcrAuthError, apply_ecr_auth

    secret = {}
    if getattr(provider, "secret", None) is not None:
        secret = dict(provider.secret.secret or {})
    try:
        secret = apply_ecr_auth(provider.uid, secret)
    except EcrAuthError as exc:
        raise EngineError(failures.failure(failures.FAILURE_AUTH, str(exc))) from None
    env: dict[str, str] = {}
    secrets: list[str] = []
    username = str(secret.get("registry_username") or "")
    password = str(secret.get("registry_password") or "")
    token = str(secret.get("registry_token") or "")
    if username and password:
        env.update(TRIVY_USERNAME=username, TRIVY_PASSWORD=password)
        secrets.append(password)
    elif token:
        env["TRIVY_REGISTRY_TOKEN"] = token
        secrets.append(token)
    if secret.get("registry_insecure"):
        env["TRIVY_INSECURE"] = "true"
    return env, tuple(secrets)


def prepare_units(
    *,
    mode: str,
    config: dict[str, Any],
    provider,
    work_dir: Path,
    limits: dict[str, int],
    ref: str | None = None,
) -> list[ScanUnit]:
    """Fetch or write the scan input and describe the engine invocations.

    Args:
        ref: Branch or tag a repository unit reads (SSH clones check it out;
            HTTPS scans get it as an engine option). Default branch if empty.

    Raises:
        EngineError: The input cannot be prepared.
    """
    from cloudsneeker.git_ssh import is_ssh_url
    from cloudsneeker_api.services import trivy as hub

    if mode in ("fs", "rootfs"):
        if not config.get("archive_b64"):
            raise EngineError(
                failures.failure(failures.FAILURE_INPUT, "No archive was uploaded.")
            )
        root = safe_extract(str(config["archive_b64"]), work_dir, limits)
        return [ScanUnit(caps.TARGETS[mode]["command"], str(root), label="archive")]

    if mode in ("repo", "iac"):
        url = str(config.get("repository_url") or provider.uid or "").strip()
        if not url:
            raise EngineError(
                failures.failure(failures.FAILURE_INPUT, "No repository URL.")
            )
        if is_ssh_url(url):
            clone_dir = work_dir / "repository"
            try:
                branch = hub.checkout_ssh_repository(
                    url, provider, clone_dir, ref=ref or None
                )
            except hub.TrivyHubError as exc:
                raise EngineError(
                    failures.failure(failures.FAILURE_AUTH, str(exc))
                ) from None
            # A plain directory has no Git metadata to select a ref from.
            return [
                ScanUnit(
                    "filesystem",
                    str(clone_dir),
                    label=url,
                    option_overrides={"branch": None, "tag": None, "commit": None},
                    branch=branch,
                )
            ]
        scan_url, env, secrets = hub.repo_scan_target(url, provider)
        return [
            ScanUnit(
                "repository",
                scan_url,
                label=url,
                env=env,
                secrets=secrets,
                branch=str(ref or ""),
            )
        ]

    if mode == "sbom":
        text = str(config.get("sbom") or "")
        try:
            document: Any = json.loads(text)
        except json.JSONDecodeError:
            document = text
        fmt = sbom.detect_document_format(document)
        if not fmt:
            raise EngineError(
                failures.failure(
                    failures.FAILURE_INPUT,
                    "The document is not CycloneDX JSON or SPDX (JSON or tag-value).",
                )
            )
        if fmt == "cyclonedx":
            suffix = "cdx.json"
        else:
            suffix = "spdx.json" if isinstance(document, dict) else "spdx"
        path = work_dir / f"document.{suffix}"
        path.write_text(text, encoding="utf-8")
        return [ScanUnit("sbom", str(path), label="sbom", sbom_format=fmt)]

    if mode == "k8s":
        try:
            env = hub._kubeconfig_env(provider, work_dir)
        except hub.TrivyHubError as exc:
            raise EngineError(
                failures.failure(failures.FAILURE_INPUT, str(exc))
            ) from None
        context = str(config.get("context") or "").strip()
        overrides: dict[str, Any] = {}
        namespace = str(config.get("namespace") or "").strip()
        if namespace:
            overrides["include_namespaces"] = [namespace]
        return [
            ScanUnit(
                "kubernetes",
                context or None,
                label=context or str(provider.uid or "cluster"),
                env=env,
                option_overrides=overrides,
            )
        ]

    if mode == "image":
        images = [
            str(item).strip()
            for item in config.get("images") or []
            if str(item).strip()
        ]
        if not images:
            images = [str(provider.uid or "").strip()]
        images = [item for item in images if item]
        if not images:
            raise EngineError(
                failures.failure(failures.FAILURE_INPUT, "No image reference.")
            )
        if len(images) > limits["max_images_per_run"]:
            raise EngineError(
                failures.failure(
                    failures.FAILURE_INPUT,
                    f"A scan covers at most {limits['max_images_per_run']} images.",
                )
            )
        env, secrets = _image_environment(provider)
        many = len(images) > 1
        return [
            ScanUnit(
                "image",
                image,
                label=image,
                scope=image_scope(image) if many else "",
                env=env,
                secrets=secrets,
            )
            for image in images
        ]

    raise EngineError(
        failures.failure(failures.FAILURE_INPUT, f"Unknown target type: {mode}.")
    )


# --- Process ------------------------------------------------------------------


@dataclass
class ProcessResult:
    exit_code: int | None
    timed_out: bool
    cancelled: bool
    stdout_path: Path
    stderr: str
    duration_ms: int


def _kill(process: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass


def run_process(
    argv: list[str],
    *,
    env: dict[str, str],
    cwd: Path,
    timeout: int,
    is_cancelled,
    stdout_path: Path,
    stderr_path: Path,
) -> ProcessResult:
    """Run the engine with stdout and stderr in separate files.

    Args:
        argv: Argument list; never passed through a shell.
        env: Complete environment for the child.
        cwd: Working directory (the scan directory).
        timeout: Wall-clock limit in seconds.
        is_cancelled: Callable polled while the process runs.
        stdout_path: File for the report.
        stderr_path: File for the log.
    """
    started = time.monotonic()
    timed_out = cancelled = False
    with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
        process = subprocess.Popen(  # noqa: S603 - argv list, no shell
            argv,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            env=env,
            cwd=str(cwd),
            start_new_session=os.name == "posix",
        )
        try:
            while True:
                try:
                    process.wait(timeout=POLL_SECONDS)
                    break
                except subprocess.TimeoutExpired:
                    if time.monotonic() - started > timeout:
                        timed_out = True
                    elif is_cancelled():
                        cancelled = True
                    else:
                        continue
                    _kill(process)
                    process.wait(timeout=30)
                    break
        finally:
            if process.poll() is None:
                _kill(process)
    stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
    return ProcessResult(
        exit_code=process.returncode,
        timed_out=timed_out,
        cancelled=cancelled,
        stdout_path=stdout_path,
        stderr=stderr,
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def redact_argv(argv: list[str], secrets: tuple[str, ...]) -> list[str]:
    """Argument list safe to store: secrets and scan paths removed."""
    from cloudsneeker.git_auth import redact

    return [redact(item, *secrets) if secrets else item for item in argv]


def drop_nul_chars(value: Any) -> Any:
    """Remove NUL characters from every string in a report.

    A code snippet copied from a binary-ish file can carry ``\x00``, which
    PostgreSQL refuses in text and JSON columns ("unsupported Unicode escape
    sequence"), so the whole scan failed to save.
    """
    if isinstance(value, str):
        return value.replace("\x00", "") if "\x00" in value else value
    if isinstance(value, dict):
        return {
            drop_nul_chars(key): drop_nul_chars(item) for key, item in value.items()
        }
    if isinstance(value, list):
        return [drop_nul_chars(item) for item in value]
    return value


def mask_report(report: dict[str, Any]) -> dict[str, Any]:
    """Mask every secret finding of a raw report before it is stored."""

    def mask_results(results: Any) -> None:
        for result in results if isinstance(results, list) else []:
            if not isinstance(result, dict):
                continue
            if isinstance(result.get("Secrets"), list):
                result["Secrets"] = [
                    parser.mask_secret(item) if isinstance(item, dict) else item
                    for item in result["Secrets"]
                ]
            for modified in result.get("ExperimentalModifiedFindings") or []:
                if (
                    isinstance(modified, dict)
                    and str(modified.get("Type")).lower() == "secret"
                    and isinstance(modified.get("Finding"), dict)
                ):
                    modified["Finding"] = parser.mask_secret(modified["Finding"])

    mask_results(report.get("Results"))
    for key in ("Resources", "Findings"):
        for resource in report.get(key) or []:
            if isinstance(resource, dict):
                mask_results(resource.get("Results"))
    return report


def read_report(path: Path, max_bytes: int) -> dict[str, Any]:
    """Load the JSON report written by the engine.

    Raises:
        EngineError: Empty, oversized, malformed or non-object output.
    """
    size = path.stat().st_size if path.exists() else 0
    if size == 0:
        raise EngineError(
            failures.failure(failures.FAILURE_OUTPUT, "It wrote no report.")
        )
    if size > max_bytes:
        raise EngineError(
            failures.failure(
                failures.FAILURE_OUTPUT, "The report exceeds the size limit."
            )
        )
    try:
        with open(path, "rb") as handle:
            report = json.load(handle)
    except (ValueError, UnicodeDecodeError) as exc:
        raise EngineError(
            failures.failure(
                failures.FAILURE_OUTPUT,
                f"The report is not valid JSON ({type(exc).__name__}).",
            )
        ) from None
    if not isinstance(report, dict):
        raise EngineError(
            failures.failure(
                failures.FAILURE_OUTPUT, "The report root is not an object."
            )
        )
    return report


def store_report(directory: Path, index: int, report: dict[str, Any]) -> str:
    """Write a masked report, gzip compressed, readable by the owner only."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / REPORT_FILE.format(index=index)
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(report, handle, separators=(",", ":"))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path.name


# --- Options and policies -----------------------------------------------------


def profile_options(
    tenant_id: str, ref: str, *, using: str | None = None
) -> dict[str, Any]:
    """Options of a built-in or tenant profile.

    Raises:
        OptionError: Unknown or disabled profile.
    """
    from cloudsneeker_api.models import AppSecScanProfile

    ref = str(ref or "").strip()
    if ref.startswith(caps.BUILTIN_PROFILE_PREFIX):
        profile = caps.BUILTIN_PROFILES.get(ref[len(caps.BUILTIN_PROFILE_PREFIX) :])
        if profile is None:
            raise OptionError(f"Unknown scan profile: {ref}.")
        return dict(profile["options"])
    manager = (
        AppSecScanProfile.objects.using(using) if using else AppSecScanProfile.objects
    )
    try:
        profile_id = uuid.UUID(ref)
    except ValueError:
        raise OptionError(f"Unknown scan profile: {ref}.") from None
    row = manager.filter(tenant_id=tenant_id, id=profile_id).first()
    if row is None:
        raise OptionError("The scan profile no longer exists.")
    if not row.enabled:
        raise OptionError(f"The scan profile '{row.name}' is disabled.")
    return dict(row.options or {})


def effective_profile_ref(target, settings_row) -> str:
    """Profile a target runs with: its own, its application's, the tenant
    default for its type, then the built-in default."""
    config = target.config or {}
    if config.get("profile"):
        return str(config["profile"])
    application = getattr(target, "application", None)
    if application is not None and application.default_profile_ref:
        return application.default_profile_ref
    defaults = (settings_row.default_profiles if settings_row else None) or {}
    return str(defaults.get(target.mode) or caps.DEFAULT_PROFILE_REF)


def resolve_options(
    *, tenant_id: str, target, settings_row=None, using: str | None = None
) -> tuple[str, dict[str, Any]]:
    """Return ``(profile_ref, options)`` for a run of ``target``.

    Target options (``config.options``, and the ``scanners`` and ``severity``
    keys older targets store) override the profile. Profile values the
    target type does not support are dropped.

    Raises:
        OptionError: Invalid profile or options.
    """
    config = target.config or {}
    ref = effective_profile_ref(target, settings_row)
    has_explicit_profile = bool(config.get("profile"))
    layers = [profile_options(tenant_id, ref, using=using)]
    legacy: dict[str, Any] = {}
    # Targets saved before profiles carry their scanner list on the config.
    if not has_explicit_profile and config.get("scanners"):
        legacy["scanners"] = config["scanners"]
    severity = config.get("severity") or config.get("severities")
    if severity:
        legacy["severities"] = (
            [item.strip() for item in severity.split(",")]
            if isinstance(severity, str)
            else list(severity)
        )
    layers.append(legacy)
    layers.append(
        config.get("options") if isinstance(config.get("options"), dict) else None
    )
    return ref, validate_options(target.mode, merge_options(*layers), strict=False)


def enabled_policies(
    tenant_id: str, *, using: str | None = None
) -> list[dict[str, Any]]:
    """Enabled tenant policies whose content validates."""
    from cloudsneeker_api.models import AppSecPolicy

    manager = AppSecPolicy.objects.using(using) if using else AppSecPolicy.objects
    rows = manager.filter(tenant_id=tenant_id, enabled=True).order_by("kind", "name")
    return [
        {
            "id": str(row.id),
            "kind": row.kind,
            "name": row.name,
            "version": row.version,
            "content": row.content,
        }
        for row in rows
        if policies.validate_policy(row.kind, row.content).valid
    ]


# --- Run ----------------------------------------------------------------------


@dataclass
class UnitOutcome:
    unit: ScanUnit
    parsed: parser.ParsedReport | None = None
    failure: failures.Failure | None = None
    exit_code: int | None = None
    stderr_tail: str = ""
    command: list[str] = field(default_factory=list)
    attempts: int = 0
    duration_ms: int = 0
    artifact: str = ""
    # Re-run without remote dependency lookups after a registry rate limit.
    offline_fallback: bool = False


def run_unit(
    *,
    unit: ScanUnit,
    index: int,
    mode: str,
    options: dict[str, Any],
    policy_items: list[dict[str, Any]],
    work_dir: Path,
    artifact_dir: Path,
    limits: dict[str, int],
    is_cancelled,
    binary: str,
    sleep=time.sleep,
) -> UnitOutcome:
    """Run one engine invocation with retries, parse and store its report."""
    from cloudsneeker_api.services.trivy import scrub_secrets
    from cloudsneeker_api.services.vuln_db import scan_cache_env

    outcome = UnitOutcome(unit=unit)
    unit_options = merge_options(options, unit.option_overrides)
    for name, value in unit.option_overrides.items():
        if value is None:
            unit_options.pop(name, None)
    unit_dir = work_dir / f"unit-{index}"
    unit_dir.mkdir(parents=True, exist_ok=True)
    files = policies.write_policy_files(
        policy_items,
        unit_dir,
        target_type=mode,
        scanners=list(unit_options.get("scanners") or []),
        sbom_format=unit.sbom_format,
    )
    # The profile's target type decides valid flags; an SSH repository runs
    # the filesystem command, which accepts the same ones minus Git refs.
    flags = build_scan_args(
        mode, unit_options, has_vex=files.has_vex, extra_flags=files.flags
    )
    timeout = engine_timeout_seconds(unit_options, limits["default_timeout_seconds"])
    if "--timeout" not in flags:
        flags.extend(["--timeout", f"{timeout}s"])
    argv = [binary, unit.subcommand, *flags]
    if unit.target_arg:
        argv.append(unit.target_arg)
    outcome.command = redact_argv(argv, unit.secrets)
    env = {**base_environment(), **scan_cache_env(unit_dir), **unit.env}

    result: ProcessResult | None = None
    for attempt in range(1, limits["max_attempts"] + 1):
        outcome.attempts = attempt
        result = run_process(
            argv,
            env=env,
            cwd=unit_dir,
            # The engine enforces its own timeout; this is the backstop.
            timeout=timeout + 60,
            is_cancelled=is_cancelled,
            stdout_path=unit_dir / "report.json",
            stderr_path=unit_dir / "stderr.log",
        )
        outcome.duration_ms += result.duration_ms
        outcome.exit_code = result.exit_code
        stderr = scrub_secrets(result.stderr, unit.secrets)
        outcome.stderr_tail = failures.stderr_tail(stderr)
        if result.cancelled:
            outcome.failure = failures.failure(failures.FAILURE_CANCELLED)
            return outcome
        if result.timed_out:
            outcome.failure = failures.failure(
                failures.FAILURE_TIMEOUT, f"The limit was {timeout} seconds."
            )
            return outcome
        if result.exit_code == 0:
            outcome.failure = None
            break
        outcome.failure = failures.classify_failure(result.exit_code, stderr)
        if (
            outcome.failure.kind == failures.FAILURE_RATE_LIMITED
            and OFFLINE_FLAG not in argv
            and attempt < limits["max_attempts"]
        ):
            # Retry at once without remote metadata; the scan is then
            # recorded as incomplete (see ``OFFLINE_FALLBACK_REASON``).
            argv = [*argv[:2], OFFLINE_FLAG, *argv[2:]]
            outcome.command = redact_argv(argv, unit.secrets)
            outcome.offline_fallback = True
            continue
        if not outcome.failure.retryable or attempt == limits["max_attempts"]:
            return outcome
        delay = failures.retry_delay_seconds(attempt)
        waited = 0.0
        while waited < delay:
            if is_cancelled():
                outcome.failure = failures.failure(failures.FAILURE_CANCELLED)
                return outcome
            sleep(min(POLL_SECONDS, delay - waited))
            waited += POLL_SECONDS

    if result is None:
        # Only reachable when max_attempts is below 1. A check rather than an
        # assert, which `python -O` strips.
        outcome.failure = failures.failure(
            failures.FAILURE_ENGINE, "The scanner was not started."
        )
        return outcome
    try:
        report = read_report(result.stdout_path, limits["max_report_bytes"])
    except EngineError as exc:
        outcome.failure = exc.failure
        return outcome
    report = drop_nul_chars(mask_report(scrub_secrets(report, unit.secrets)))
    outcome.parsed = parser.parse_report(report, mode=mode, scope=unit.scope)
    try:
        outcome.artifact = store_report(artifact_dir, index, report)
    except OSError:
        logger.warning("Raw scan report could not be stored", exc_info=True)
    return outcome


def _update_run(run, using: str, **fields: Any) -> None:
    """Write run fields on the admin connection (commits immediately)."""
    from django.utils import timezone

    type(run).objects.using(using).filter(tenant_id=run.tenant_id, id=run.id).update(
        updated_at=timezone.now(), **fields
    )
    for name, value in fields.items():
        setattr(run, name, value)


def cancel_requested(run, using: str) -> bool:
    return (
        type(run)
        .objects.using(using)
        .filter(tenant_id=run.tenant_id, id=run.id, cancel_requested_at__isnull=False)
        .exists()
    )


def _application_context(target):
    from cloudsneeker_api.appsec.lifecycle import AppContext

    application = getattr(target, "application", None)
    if application is None:
        return AppContext()
    return AppContext(
        criticality=application.criticality,
        environment=application.environment,
        internet_exposed=application.internet_exposed,
    )


def tenant_settings(tenant_id: str, *, using: str | None = None):
    from cloudsneeker_api.models import AppSecSettings

    manager = AppSecSettings.objects.using(using) if using else AppSecSettings.objects
    return manager.filter(tenant_id=tenant_id).first()


def persist_results(
    *,
    tenant_id: str,
    run,
    target,
    provider,
    findings: list[parser.NormalizedFinding],
    components: list[parser.NormalizedComponent],
    coverage,
    artifact_name: str,
    artifact_type: str,
    inventory_source: str,
    document_format: str,
    shared_rows_for,
    scan_name: str,
    using: str,
) -> dict[str, Any]:
    """Store findings, inventory and the shared rows in one transaction.

    Args:
        shared_rows_for: Callable ``uids -> list[row]`` building the shared
            ``Finding`` rows once UIDs are assigned.

    Returns:
        ``{"lifecycle", "scan_id", "sbom_id", "finding_count"}``.
    """
    from cloudsneeker_api.appsec import inventory, lifecycle
    from cloudsneeker_api.appsec.risk import merge_risk_config, merge_sla_days
    from cloudsneeker_api.services.trivy_import import import_trivy_report
    from django.db import transaction
    from django.utils import timezone

    settings_row = tenant_settings(tenant_id, using=using)
    retention = (settings_row.retention if settings_row else None) or {}
    now = timezone.now()
    with transaction.atomic(using=using):
        outcome = lifecycle.reconcile(
            tenant_id=tenant_id,
            target=target,
            run=run,
            findings=findings,
            coverage=coverage,
            now=now,
            risk_config=merge_risk_config(settings_row.risk if settings_row else None),
            sla_days=merge_sla_days(settings_row.sla_days if settings_row else None),
            context=_application_context(target),
            using=using,
        )
        record = inventory.store_inventory(
            tenant_id=tenant_id,
            target=target,
            run=run,
            components=components,
            findings=findings,
            artifact_name=artifact_name,
            artifact_type=artifact_type,
            source=inventory_source,
            document_format=document_format,
            keep_versions=int(
                retention.get("sbom_versions") or inventory.DEFAULT_SBOM_VERSIONS_KEPT
            ),
            using=using,
        )
        rows = shared_rows_for(outcome.uids)
        scan = import_trivy_report(
            tenant_id=tenant_id,
            provider=provider,
            report={},
            mode=target.mode,
            scan_name=scan_name,
            started_at=run.started_at,
            rows=rows,
        )
    from cloudsneeker_api.services.alert_dispatch import enqueue_after_scan
    from cloudsneeker_api.services.area_mute import reconcile_scan

    # The provider scan applies the mutelist itself; application scans do it
    # here, before alerts read the rows.
    try:
        reconcile_scan(tenant_id, str(scan.id), str(target.id))
    except Exception:  # noqa: BLE001 - muting must not fail a finished scan
        logger.exception("Mute rules not applied to scan %s", scan.id)
    enqueue_after_scan(tenant_id, scan_id=str(scan.id), using=using)
    return {
        "lifecycle": outcome.to_dict(),
        "scan_id": str(scan.id),
        "sbom_id": str(record.id) if record else None,
        "finding_count": len(rows),
    }


def _fail(run, using: str, failure: failures.Failure, **fields: Any) -> dict[str, str]:
    from cloudsneeker_api.models import TrivyRun
    from cloudsneeker_api.services.brand_text import scrub_engine_text
    from django.utils import timezone

    cancelled = failure.kind == failures.FAILURE_CANCELLED
    status = TrivyRun.Status.CANCELLED if cancelled else TrivyRun.Status.FAILED
    _update_run(
        run,
        using,
        status=status,
        finished_at=timezone.now(),
        error=scrub_engine_text(failure.message)[:4000],
        error_class=failure.kind,
        **fields,
    )
    return {"status": status, "run_id": str(run.id)}


OFFLINE_FLAG = "--offline-scan"
OFFLINE_FALLBACK_REASON = (
    "A package registry rate-limited the scan, so it ran without remote "
    "dependency metadata; some transitive dependencies may be missing."
)

# Seconds a run waits before checking for a free slot again.
DEFER_SECONDS = 30


def running_slots_full(tenant_id: str, *, using: str | None = None) -> bool:
    """Whether the organization already runs as many scans as it may.

    A run still marked running after the longest a scan can take (timeout
    times attempts, plus a margin) is treated as dead: a worker restart can
    leave one behind, and it must not hold a slot forever.
    """
    from datetime import timedelta

    from cloudsneeker_api.models import TrivyRun
    from django.utils import timezone

    limits = engine_limits()
    longest = limits["default_timeout_seconds"] * limits["max_attempts"] + 600
    manager = TrivyRun.objects.using(using) if using else TrivyRun.objects
    running = manager.filter(
        tenant_id=tenant_id,
        status=TrivyRun.Status.RUNNING,
        started_at__gte=timezone.now() - timedelta(seconds=longest),
    ).count()
    return running >= limits["max_active_runs_per_tenant"]


def execute_run(*, tenant_id: str, run_id: str) -> dict[str, str]:
    """Execute one pending run. Never raises for a scan failure.

    While the organization runs as many scans as it may, the run stays
    pending and is dispatched again after ``DEFER_SECONDS``.
    """
    from api.db_router import MainRouter
    from cloudsneeker_api.models import TrivyRun
    from cloudsneeker_api.services import trivy as hub
    from django.utils import timezone

    using = MainRouter.admin_db
    run = (
        TrivyRun.objects.using(using)
        .select_related("target", "target__application", "provider", "provider__secret")
        .filter(tenant_id=tenant_id, id=run_id)
        .first()
    )
    if run is None:
        raise hub.TrivyHubError(f"Scan run {run_id} was not found.")
    if run.status != TrivyRun.Status.PENDING:
        return {"status": run.status, "run_id": str(run_id)}
    if run.cancel_requested_at is not None:
        return _fail(run, using, failures.failure(failures.FAILURE_CANCELLED))
    if running_slots_full(tenant_id, using=using):
        from cloudsneeker_api.tasks import trivy_scan_task

        trivy_scan_task.apply_async(
            kwargs={"tenant_id": tenant_id, "run_id": str(run_id)},
            countdown=DEFER_SECONDS,
        )
        return {"status": "deferred", "run_id": str(run_id)}

    target, provider, mode = run.target, run.provider, run.target.mode
    started = timezone.now()
    _update_run(
        run,
        using,
        status=TrivyRun.Status.RUNNING,
        started_at=started,
        error="",
        error_class="",
        engine=ENGINE_OPENGREP if mode == "sast" else caps.ENGINE_NAME,
    )

    work_dir = Path(tempfile.mkdtemp(prefix="cloudsneeker-appsec-"))
    try:
        try:
            config = hub.validate_target_config(mode, target.config, strict=False)
            hub.assert_provider_matches_mode(provider, mode, config)
        except hub.TrivyHubError as exc:
            return _fail(run, using, failures.failure(failures.FAILURE_INPUT, str(exc)))

        if mode == "sast":
            return _execute_code_scan(run, target, provider, config, using)

        if mode not in direct_modes() or (
            mode == "image" and is_registry_wide(provider.uid, config)
        ):
            return _hand_to_provider_scan(run, target, provider, using)

        limits = engine_limits()
        try:
            settings_row = tenant_settings(tenant_id, using=using)
            profile_ref, options = resolve_options(
                tenant_id=tenant_id,
                target=target,
                settings_row=settings_row,
                using=using,
            )
            options = apply_target_branch(config, options)
            binary = resolve_binary()
            status = engine_status()
            units = prepare_units(
                mode=mode,
                config=config,
                provider=provider,
                work_dir=work_dir,
                limits=limits,
                ref=options.get("branch") or options.get("tag") or None,
            )
        except OptionError as exc:
            return _fail(run, using, failures.failure(failures.FAILURE_INPUT, str(exc)))
        except EngineError as exc:
            return _fail(run, using, exc.failure)

        _update_run(
            run,
            using,
            engine_version=status["version"],
            profile_ref=profile_ref,
            options=options,
            database=status.get("vulnerability_db") or {},
        )
        policy_items = enabled_policies(tenant_id, using=using)
        artifact_dir = run_artifact_dir(tenant_id, str(run.id))
        outcomes = [
            run_unit(
                unit=unit,
                index=index,
                mode=mode,
                options=options,
                policy_items=policy_items,
                work_dir=work_dir,
                artifact_dir=artifact_dir,
                limits=limits,
                is_cancelled=lambda: cancel_requested(run, using),
                binary=binary,
            )
            for index, unit in enumerate(units)
        ]
        return _finish_engine_run(
            run, target, provider, options, outcomes, artifact_dir, using
        )
    except Exception as exc:  # noqa: BLE001 - the run must not stay "running"
        logger.exception("Application security scan failed unexpectedly run=%s", run_id)
        return _fail(
            run,
            using,
            failures.failure(
                failures.FAILURE_ENGINE, f"Internal error ({type(exc).__name__})."
            ),
        )
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def _finish_engine_run(run, target, provider, options, outcomes, artifact_dir, using):
    from cloudsneeker_api.appsec import lifecycle
    from cloudsneeker_api.appsec.shared_rows import shared_row
    from cloudsneeker_api.models import TrivyRun
    from django.utils import timezone

    mode = target.mode
    first = outcomes[0]
    record = {
        "command": first.command,
        "exit_code": first.exit_code,
        "stderr_tail": "\n".join(
            item.stderr_tail for item in outcomes if item.stderr_tail
        )[-4000:],
        "attempts": max(item.attempts for item in outcomes),
        "duration_ms": sum(item.duration_ms for item in outcomes),
    }
    succeeded = [item for item in outcomes if item.parsed is not None]
    failed = [item for item in outcomes if item.failure is not None]
    cancelled = next(
        (item for item in failed if item.failure.kind == failures.FAILURE_CANCELLED),
        None,
    )
    if cancelled or not succeeded:
        shutil.rmtree(artifact_dir, ignore_errors=True)
        return _fail(run, using, (cancelled or failed[0]).failure, **record)

    findings: list[parser.NormalizedFinding] = []
    components: list[parser.NormalizedComponent] = []
    warnings: list[str] = []
    reasons: list[str] = []
    passed = 0
    for item in succeeded:
        findings.extend(item.parsed.findings)
        components.extend(item.parsed.components)
        warnings.extend(item.parsed.warnings)
        passed += item.parsed.passed_checks
        for error in item.parsed.resource_errors:
            reasons.append(f"{error['resource']}: {error['error']}")
    for item in failed:
        reasons.append(f"{item.unit.label}: {item.failure.message}")
    for item in succeeded:
        if item.offline_fallback:
            reasons.append(f"{item.unit.label}: {OFFLINE_FALLBACK_REASON}")
    # Distinct units have distinct scopes, so fingerprints cannot collide.
    coverage = lifecycle.coverage_for(
        options, complete=not reasons, reasons=reasons[:20]
    )
    head = succeeded[0].parsed
    document_format = succeeded[0].unit.sbom_format
    metadata = dict(head.metadata)
    branch = succeeded[0].unit.branch or str(metadata.get("Branch") or "")
    if branch and not metadata.get("Branch"):
        # SSH clones are scanned as a directory, so the engine reports none.
        metadata["Branch"] = branch
    if not (options.get("tag") or options.get("commit")):
        _pin_branch(target, branch, using)

    def shared_rows_for(uids: dict[str, str]) -> list[dict[str, Any]]:
        return [
            shared_row(finding, uids[finding.fingerprint], mode=mode)
            for finding in findings
            if not finding.suppressed
        ]

    stored = persist_results(
        tenant_id=str(run.tenant_id),
        run=run,
        target=target,
        provider=provider,
        findings=findings,
        components=components,
        coverage=coverage,
        artifact_name=head.artifact_name or target.name,
        artifact_type=head.artifact_type or mode,
        inventory_source="imported" if mode == "sbom" else "generated",
        document_format=document_format,
        shared_rows_for=shared_rows_for,
        scan_name=f"Trivy {mode}: {target.name}",
        using=using,
    )
    stats = parser.finding_stats(findings)
    stats.update(
        lifecycle=stored["lifecycle"],
        components=len(components),
        passed_checks=passed,
        units=len(outcomes),
        failed_units=len(failed),
    )
    targets: list[str] = []
    for item in succeeded:
        targets.extend(item.parsed.result_targets)
    _update_run(
        run,
        using,
        status=TrivyRun.Status.COMPLETED,
        finished_at=timezone.now(),
        scan_id=stored["scan_id"],
        summary={
            "mode": mode,
            "path": "trivy_cli",
            "scan_id": stored["scan_id"],
            "finding_count": stored["finding_count"],
            "sbom_id": stored["sbom_id"],
            "partial": bool(reasons),
            **({"branch": branch} if branch else {}),
        },
        output={
            "result_targets": targets[:50],
            "metadata": metadata,
            "warnings": warnings[:20],
            "artifacts": [item.artifact for item in succeeded if item.artifact],
        },
        coverage=coverage.to_dict(),
        stats=stats,
        artifact_path=str(artifact_dir.relative_to(artifact_root())).replace("\\", "/")
        if any(item.artifact for item in succeeded)
        else "",
        **record,
    )
    return {
        "status": TrivyRun.Status.COMPLETED,
        "run_id": str(run.id),
        "scan_id": stored["scan_id"],
    }


def _pin_branch(target, branch: str, using: str) -> None:
    """Record the branch a default-branch Git target scanned (and name it).

    Never fails the run: the scan results matter more than the label.
    """
    from cloudsneeker_api.services.repo_branches import pin_target_branch

    if not branch:
        return
    try:
        pin_target_branch(target, branch, using=using)
    except Exception:  # noqa: BLE001
        logger.warning("Could not record the branch of target %s", target.id)


def _execute_code_scan(run, target, provider, config, using):
    """Static analysis: the existing OpenGrep path plus the finding lifecycle."""
    from cloudsneeker_api.appsec import lifecycle
    from cloudsneeker_api.models import TrivyRun
    from cloudsneeker_api.services import trivy as hub
    from cloudsneeker_api.services.sast import run_opengrep_scan
    from cloudsneeker_api.services.trivy_import import (
        compact_report_output,
        opengrep_results_to_finding_rows,
    )
    from django.utils import timezone

    started = time.monotonic()
    try:
        report = run_opengrep_scan(config=config, provider=provider)
    except hub.TrivyHubError as exc:
        return _fail(run, using, failures.failure(failures.FAILURE_ENGINE, str(exc)))
    _pin_branch(target, str(report.get("cloudsneeker_branch") or ""), using)
    rows = opengrep_results_to_finding_rows(report)
    findings = parser.parse_code_rows(rows)
    fingerprint_by_uid = {
        finding.legacy_uid: finding.fingerprint for finding in findings
    }
    errors = report.get("errors")
    incomplete = isinstance(errors, list) and len(errors) > 0
    coverage = lifecycle.coverage_for(
        {"scanners": ["sast"]},
        complete=not incomplete and not config.get("exclude"),
        reasons=["Some files could not be analyzed."] if incomplete else [],
    )

    def shared_rows_for(uids: dict[str, str]) -> list[dict[str, Any]]:
        shared = []
        seen: set[str] = set()
        for row in rows:
            fingerprint = fingerprint_by_uid.get(row["uid"])
            uid = uids.get(fingerprint or "", row["uid"])
            if uid in seen:
                continue
            seen.add(uid)
            shared.append({**row, "uid": uid})
        return shared

    stored = persist_results(
        tenant_id=str(run.tenant_id),
        run=run,
        target=target,
        provider=provider,
        findings=findings,
        components=[],
        coverage=coverage,
        artifact_name=target.name,
        artifact_type="sast",
        inventory_source="generated",
        document_format="",
        shared_rows_for=shared_rows_for,
        scan_name=f"SAST: {target.name}",
        using=using,
    )
    stats = parser.finding_stats(findings)
    stats["lifecycle"] = stored["lifecycle"]
    _update_run(
        run,
        using,
        status=TrivyRun.Status.COMPLETED,
        finished_at=timezone.now(),
        scan_id=stored["scan_id"],
        summary={
            "mode": "sast",
            "path": "trivy_cli",
            "scan_id": stored["scan_id"],
            "finding_count": stored["finding_count"],
            **(
                {"branch": str(report["cloudsneeker_branch"])}
                if report.get("cloudsneeker_branch")
                else {}
            ),
        },
        output=compact_report_output(report, mode="sast"),
        coverage=coverage.to_dict(),
        stats=stats,
        duration_ms=int((time.monotonic() - started) * 1000),
        attempts=1,
    )
    return {
        "status": TrivyRun.Status.COMPLETED,
        "run_id": str(run.id),
        "scan_id": stored["scan_id"],
    }


def _hand_to_provider_scan(run, target, provider, using):
    """Registry-wide image targets (and rolled-back types) keep the provider scan."""
    from cloudsneeker_api.models import TrivyRun
    from cloudsneeker_api.services import trivy as hub
    from django.utils import timezone

    scan = hub._enqueue_provider_scan(
        tenant_id=str(run.tenant_id),
        provider=provider,
        run=run,
        scan_name=f"Trivy {target.mode}: {target.name}",
    )
    _update_run(
        run,
        using,
        scan_id=scan.id,
        status=TrivyRun.Status.COMPLETED,
        finished_at=timezone.now(),
        summary={
            "mode": target.mode,
            "path": PROVIDER_SCAN_PATH,
            "scan_id": str(scan.id),
            "finding_count": None,
        },
        output={"enqueued": True},
    )
    return {
        "status": TrivyRun.Status.COMPLETED,
        "run_id": str(run.id),
        "scan_id": str(scan.id),
    }


# --- Exports ------------------------------------------------------------------

CONVERT_FORMATS = {
    "sarif": ("sarif", "application/sarif+json", "sarif"),
    "cyclonedx": ("cyclonedx", "application/vnd.cyclonedx+json", "cdx.json"),
    "spdx-json": ("spdx-json", "application/spdx+json", "spdx.json"),
}


def load_report(run, index: int = 0) -> dict[str, Any] | None:
    """Return a stored (masked) report of a run, or ``None`` if it is gone."""
    if not run.artifact_path:
        return None
    path = artifact_root() / run.artifact_path / REPORT_FILE.format(index=index)
    if not _inside(artifact_root(), path) or not path.is_file():
        return None
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def convert_report(report: dict[str, Any], fmt: str) -> bytes:
    """Convert a stored report with the engine's ``convert`` command.

    Args:
        report: Stored standard report (not a cluster report).
        fmt: Key of :data:`CONVERT_FORMATS`.

    Raises:
        EngineError: Unknown format, cluster report, or the conversion failed.
    """
    if fmt not in CONVERT_FORMATS:
        raise EngineError(
            failures.failure(failures.FAILURE_INPUT, f"Unknown format: {fmt}.")
        )
    if "Resources" in report or "ClusterName" in report:
        raise EngineError(
            failures.failure(
                failures.FAILURE_INPUT, "A cluster report can only be exported as JSON."
            )
        )
    binary = resolve_binary()
    work_dir = Path(tempfile.mkdtemp(prefix="cloudsneeker-appsec-convert-"))
    try:
        source = work_dir / "report.json"
        output = work_dir / "converted"
        source.write_text(json.dumps(report), encoding="utf-8")
        argv = [
            binary,
            "convert",
            "--quiet",
            "--format",
            CONVERT_FORMATS[fmt][0],
            "--output",
            str(output),
        ]
        if fmt != "sarif":
            # Without an explicit scanner an SBOM format carries no vulnerabilities.
            argv.extend(["--scanners", "vuln"])
        argv.append(str(source))
        process = subprocess.run(  # noqa: S603 - argv list, no shell
            argv,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            env=base_environment(),
            cwd=str(work_dir),
        )
        if process.returncode != 0 or not output.is_file():
            raise EngineError(
                failures.classify_failure(process.returncode, process.stderr)
            )
        return output.read_bytes()
    except subprocess.TimeoutExpired:
        raise EngineError(failures.failure(failures.FAILURE_TIMEOUT)) from None
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def purge_artifacts(older_than_days: int) -> int:
    """Delete stored raw reports older than the retention window.

    Returns:
        Number of run directories removed.
    """
    root = artifact_root()
    if not root.is_dir():
        return 0
    cutoff = time.time() - older_than_days * 86400
    removed = 0
    for tenant_dir in root.iterdir():
        if not tenant_dir.is_dir():
            continue
        for run_dir in tenant_dir.iterdir():
            try:
                if run_dir.is_dir() and run_dir.stat().st_mtime < cutoff:
                    shutil.rmtree(run_dir, ignore_errors=True)
                    removed += 1
            except OSError:
                continue
    return removed
