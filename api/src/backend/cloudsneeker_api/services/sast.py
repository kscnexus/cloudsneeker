"""Static analysis (SAST) mode for Application Security targets.

The engine is OpenGrep (LGPL-2.1 fork of Semgrep OSS). It runs on a shallow
clone of the linked IaC provider's repository, or on an uploaded code archive,
with the rule packs vendored into the worker image at build time
(``cloudsneeker/deploy/docker/api.Dockerfile``). The JSON report is imported
into the shared Scan / Finding rows by
:func:`cloudsneeker_api.services.trivy_import.opengrep_results_to_finding_rows`.

Rule packs come only from permissively licensed sources (MIT / Apache-2.0).
Semgrep registry rules (``p/...``) and ``opengrep-rules`` (LGPL-2.1 plus the
Commons Clause, which forbids selling a product whose value derives from the
rules) are never used.

Nothing here logs. Tokens never leave this module unredacted.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from api.models import Provider
from cloudsneeker.git_auth import authenticated_clone_url, redact
from cloudsneeker_api.services.trivy import (
    MAX_ARCHIVE_BYTES,
    TRIVY_TIMEOUT_SECONDS,
    TrivyHubError,
    _extract_archive,
    _has_embedded_credentials,
    _repo_credentials,
    assert_supported_archive,
    scrub_secrets,
)

DEFAULT_RULES_DIR = "/opt/opengrep/rules"

# Ruleset name -> folder under the vendored rules directory. ``typescript``
# shares the JavaScript pack (its rules list both languages).
SAST_RULESETS: dict[str, str] = {
    "csharp": "csharp",
    "go": "go",
    "java": "java",
    "javascript": "javascript",
    "typescript": "javascript",
    "python": "python",
    "scala": "scala",
}

AUTO_RULESET = "auto"
ALL_RULESET = "all"

# File extension -> ruleset, used when ``rulesets`` is ``auto``.
EXTENSION_RULESETS: dict[str, str] = {
    ".cs": "csharp",
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".py": "python",
    ".scala": "scala",
    ".sc": "scala",
}

SKIP_DIRS = frozenset({".git", "node_modules", "vendor", ".venv", "venv"})
MAX_DETECT_FILES = 200_000
MAX_EXCLUDE_PATTERNS = 50
MAX_EXCLUDE_LENGTH = 200
OPENGREP_RULE_TIMEOUT_SECONDS = int(
    os.environ.get("OPENGREP_RULE_TIMEOUT_SECONDS", "30")
)
OPENGREP_JOBS = os.environ.get("OPENGREP_JOBS", "").strip()
MIN_SCAN_SECONDS = 30


def validate_sast_config(cfg: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize a SAST target config.

    Args:
        cfg: Config already copied by ``validate_target_config``.

    Returns:
        The normalized config: exactly one of ``repository_url`` or
        ``archive_b64``, ``rulesets`` (list) and ``exclude`` (list).

    Raises:
        TrivyHubError: When a field is missing or invalid.
    """
    # Trivy scanner / severity filters do not apply to OpenGrep.
    cfg.pop("scanners", None)
    cfg.pop("severity", None)
    cfg.pop("severities", None)
    if str(cfg.get("path") or "").strip():
        raise TrivyHubError(
            "config.path is not supported; set config.repository_url or "
            "upload an archive (config.archive_b64)."
        )
    cfg.pop("path", None)

    url = str(cfg.get("repository_url") or cfg.get("url") or "").strip()
    cfg.pop("url", None)
    archive = str(cfg.get("archive_b64") or "")
    if url and archive:
        raise TrivyHubError(
            "Set either config.repository_url or config.archive_b64, not both."
        )
    if not url and not archive:
        raise TrivyHubError(
            "config.repository_url or config.archive_b64 is required for sast mode."
        )
    if url:
        if _has_embedded_credentials(url):
            raise TrivyHubError(
                "config.repository_url must not contain credentials. Save the "
                "access token (and username) on the IaC provider instead."
            )
        cfg["repository_url"] = url
        cfg.pop("archive_b64", None)
    else:
        if len(archive) > MAX_ARCHIVE_BYTES * 2:
            raise TrivyHubError("Code archive exceeds the size limit.")
        assert_supported_archive(archive)
        cfg["archive_b64"] = archive
        cfg.pop("repository_url", None)

    cfg["rulesets"] = _normalize_rulesets(cfg.get("rulesets"))
    cfg["exclude"] = _normalize_exclude(cfg.get("exclude"))
    return cfg


def _normalize_rulesets(value: Any) -> list[str]:
    """Return a de-duplicated ruleset list, ``["auto"]`` when unset.

    Raises:
        TrivyHubError: When a name is not in the allowlist.
    """
    if value is None or value == "" or value == []:
        return [AUTO_RULESET]
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(i, str) for i in value):
        raise TrivyHubError("config.rulesets must be a list of ruleset names.")
    names: list[str] = []
    for item in value:
        name = item.strip().lower()
        if name not in SAST_RULESETS and name not in (AUTO_RULESET, ALL_RULESET):
            allowed = ", ".join([AUTO_RULESET, ALL_RULESET, *sorted(SAST_RULESETS)])
            raise TrivyHubError(
                f"Unknown ruleset '{item}'. Allowed: {allowed}."
            )
        if name not in names:
            names.append(name)
    if len(names) > 1 and (AUTO_RULESET in names or ALL_RULESET in names):
        raise TrivyHubError(
            "config.rulesets 'auto' and 'all' cannot be combined with other names."
        )
    return names


def _normalize_exclude(value: Any) -> list[str]:
    """Return validated exclude globs.

    Raises:
        TrivyHubError: When the list or a pattern is invalid.
    """
    if value is None or value == "":
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise TrivyHubError("config.exclude must be a list of glob patterns.")
    if len(value) > MAX_EXCLUDE_PATTERNS:
        raise TrivyHubError(
            f"config.exclude allows at most {MAX_EXCLUDE_PATTERNS} patterns."
        )
    patterns: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise TrivyHubError("config.exclude must be a list of glob patterns.")
        pattern = item.strip()
        if len(pattern) > MAX_EXCLUDE_LENGTH or "\x00" in pattern:
            raise TrivyHubError("config.exclude pattern is too long or invalid.")
        patterns.append(pattern)
    return patterns


def rules_root() -> Path:
    """Return the vendored rules directory (``OPENGREP_RULES_DIR``)."""
    return Path(os.environ.get("OPENGREP_RULES_DIR", "").strip() or DEFAULT_RULES_DIR)


def resolve_opengrep_bin() -> str:
    """Return the OpenGrep binary path.

    Raises:
        TrivyHubError: When the binary is not installed.
    """
    configured = os.environ.get("OPENGREP_BIN", "").strip()
    if configured:
        return configured
    found = shutil.which("opengrep")
    if not found:
        raise TrivyHubError("The static analysis engine was not found on the worker.")
    return found


def detect_rulesets(scan_dir: Path) -> list[str]:
    """Return the rulesets whose languages appear under ``scan_dir``.

    Args:
        scan_dir: Checked-out source tree.

    Returns:
        Sorted ruleset names; empty when no supported language was found.
    """
    found: set[str] = set()
    seen = 0
    for _root, dirs, files in os.walk(scan_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            seen += 1
            ruleset = EXTENSION_RULESETS.get(os.path.splitext(name)[1].lower())
            if ruleset:
                found.add(ruleset)
            if seen >= MAX_DETECT_FILES or len(found) == len(EXTENSION_RULESETS):
                return sorted(found)
    return sorted(found)


def resolve_rule_dirs(
    rulesets: list[str], scan_dir: Path, root: Path | None = None
) -> list[Path]:
    """Map ruleset names to existing vendored rule directories.

    ``auto`` uses the languages found in ``scan_dir`` and falls back to every
    pack when none is found; ``all`` uses every pack.

    Args:
        rulesets: Normalized ruleset names.
        scan_dir: Source tree, read only for ``auto``.
        root: Rules directory; defaults to :func:`rules_root`.

    Returns:
        De-duplicated rule directories in a stable order.

    Raises:
        TrivyHubError: When none of the selected packs is installed.
    """
    root = root or rules_root()
    names = list(rulesets or [AUTO_RULESET])
    if names == [AUTO_RULESET]:
        names = detect_rulesets(scan_dir) or [ALL_RULESET]
    if names == [ALL_RULESET]:
        names = sorted(SAST_RULESETS)

    dirs: list[Path] = []
    for name in names:
        folder = SAST_RULESETS.get(name)
        if folder is None:
            continue
        path = root / folder
        if path.is_dir() and path not in dirs:
            dirs.append(path)
    if not dirs:
        raise TrivyHubError(
            "No static analysis rules are installed for the selected rulesets."
        )
    return dirs


def build_opengrep_command(
    *,
    binary: str,
    rule_dirs: list[Path],
    exclude: list[str],
    timeout_seconds: int = OPENGREP_RULE_TIMEOUT_SECONDS,
    jobs: str = OPENGREP_JOBS,
) -> list[str]:
    """Build the OpenGrep argv for a scan of the current directory.

    The scan runs with ``cwd`` set to the source tree, so reported paths are
    relative to it. OpenGrep has no telemetry flag (it only sends metrics to
    the Semgrep registry, which is never used); ``--disable-version-check``
    keeps it offline.

    Args:
        binary: OpenGrep binary path.
        rule_dirs: Vendored rule directories, one ``--config`` each.
        exclude: Glob patterns, one ``--exclude`` each.
        timeout_seconds: Per-rule, per-file timeout.
        jobs: Optional parallel job count.

    Returns:
        The argv list.
    """
    argv = [binary, "scan", "--json", "--disable-version-check"]
    for rule_dir in rule_dirs:
        argv.append(f"--config={rule_dir}")
    for pattern in exclude:
        argv.append(f"--exclude={pattern}")
    argv.append(f"--timeout={int(timeout_seconds)}")
    if jobs and jobs.isdigit():
        argv.append(f"--jobs={jobs}")
    argv.append(".")
    return argv


def clone_repository(
    repository_url: str, provider: Provider, dest: Path
) -> tuple[str, ...]:
    """Shallow-clone the provider's repository into ``dest``.

    Uses dulwich (the API image has no ``git`` binary) with the token from
    the IaC provider secret, like the IaC provider. ``.git`` is removed after
    the checkout so the remote URL with the token is not left on disk.

    Args:
        repository_url: Repository URL from the target config.
        provider: Linked IaC provider.
        dest: Empty directory to clone into.

    Returns:
        Secrets (authenticated URL and token) to redact from any output.

    Raises:
        TrivyHubError: When the clone fails; the message never has a token.
    """
    from dulwich import porcelain

    token, username = _repo_credentials(provider)
    clone_url = authenticated_clone_url(repository_url, token or None, username)
    secrets = tuple(s for s in (clone_url, token) if s and s != repository_url)
    try:
        porcelain.clone(clone_url, str(dest), depth=1, errstream=io.BytesIO())
    except Exception as exc:  # noqa: BLE001 - never surface a token
        raise TrivyHubError(
            f"Repository clone failed: {redact(str(exc), *secrets)}"
        ) from None
    shutil.rmtree(dest / ".git", ignore_errors=True)
    return secrets


def _relative_path(path: str, scan_dir: Path) -> str:
    """Return ``path`` relative to ``scan_dir`` without a ``./`` prefix."""
    value = str(path or "")
    root = str(scan_dir).rstrip("/\\")
    for sep in ("/", "\\"):
        if value.startswith(root + sep):
            value = value[len(root) + 1 :]
            break
    while value.startswith("./"):
        value = value[2:]
    return value


def normalize_report(report: dict[str, Any], scan_dir: Path) -> dict[str, Any]:
    """Make result paths relative to the source tree.

    Stable relative paths keep finding UIDs equal across runs and keep the
    worker's temp directory out of the findings.

    Args:
        report: Parsed OpenGrep JSON.
        scan_dir: Source tree the scan ran in.

    Returns:
        ``report`` with ``results[].path`` and ``errors[].path`` rewritten.
    """
    for key in ("results", "errors"):
        items = report.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("path"), str):
                item["path"] = _relative_path(item["path"], scan_dir)
    return report


def run_opengrep_scan(*, config: dict[str, Any], provider: Provider) -> dict[str, Any]:
    """Fetch the code, run OpenGrep, and return its JSON report.

    The clone and the scan share one budget of ``TRIVY_HUB_TIMEOUT_SECONDS``.

    Args:
        config: Validated SAST target config.
        provider: Linked IaC provider.

    Returns:
        The OpenGrep report with relative paths, secrets scrubbed, and
        ``cloudsneeker_rulesets`` listing the rule packs used.

    Raises:
        TrivyHubError: When the clone or scan fails or times out.
    """
    work_dir = Path(tempfile.mkdtemp(prefix="cloudsneeker-sast-"))
    secrets: tuple[str, ...] = ()
    started = time.monotonic()
    try:
        if config.get("repository_url"):
            scan_dir = work_dir / "src"
            scan_dir.mkdir()
            secrets = clone_repository(str(config["repository_url"]), provider, scan_dir)
        else:
            scan_dir = _extract_archive(str(config["archive_b64"]), work_dir)

        rule_dirs = resolve_rule_dirs(list(config.get("rulesets") or []), scan_dir)
        argv = build_opengrep_command(
            binary=resolve_opengrep_bin(),
            rule_dirs=rule_dirs,
            exclude=list(config.get("exclude") or []),
        )
        remaining = TRIVY_TIMEOUT_SECONDS - int(time.monotonic() - started)
        process = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            cwd=str(scan_dir),
            env={**os.environ},
            timeout=max(remaining, MIN_SCAN_SECONDS),
            check=False,
        )
        # Exit 1 means findings; any JSON on stdout is still a report.
        stdout = process.stdout or ""
        if not stdout.strip():
            stderr = redact((process.stderr or "").strip()[-2000:], *secrets)
            raise TrivyHubError(
                stderr
                or f"Static analysis produced no output (exit {process.returncode})."
            )
        try:
            report = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise TrivyHubError(
                f"Static analysis returned invalid JSON: {redact(str(exc), *secrets)}"
            ) from None
        if not isinstance(report, dict):
            raise TrivyHubError("Static analysis JSON root must be an object.")
        report = normalize_report(report, scan_dir)
        report["cloudsneeker_rulesets"] = [path.name for path in rule_dirs]
        return scrub_secrets(report, secrets)
    except subprocess.TimeoutExpired:
        raise TrivyHubError("Static analysis timed out.") from None
    except TrivyHubError:
        raise
    except Exception as exc:  # noqa: BLE001 - never surface a token in errors
        if not secrets:
            raise
        raise TrivyHubError(
            f"Static analysis could not run: {redact(str(exc), *secrets)}"
        ) from None
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
