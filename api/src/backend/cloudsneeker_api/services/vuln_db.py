"""Shared Trivy vulnerability database cache (EB-047).

A Celery Beat task downloads the vulnerability database (and the Java
database) into a new snapshot directory on shared storage, then points
``current`` at it. Each Application Security scan gets its own cache
directory whose ``db`` and ``java-db`` entries link into the current
snapshot, so the scan skips the download while the snapshot is fresh and
still keeps its own read-write artifact cache. Trivy opens the databases
read-only, so concurrent scans can share one snapshot.

When no snapshot exists or it is older than ``MAX_AGE``, scans fall back to
Trivy's own download, as before.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

CACHE_DIR_ENV = "CLOUDSNEEKER_VULN_DB_CACHE_DIR"
MAX_AGE = timedelta(hours=24)
KEEP_SNAPSHOTS = 2
REFRESH_TIMEOUT_SECONDS = 1800

CURRENT = "current"
SNAPSHOTS = "snapshots"
MARKER = "snapshot.json"


class VulnDbError(Exception):
    """The vulnerability database could not be refreshed."""


@dataclass(frozen=True)
class Snapshot:
    path: Path
    refreshed_at: datetime
    java_db: bool

    def age(self, now: datetime | None = None) -> timedelta:
        return (now or datetime.now(UTC)) - self.refreshed_at

    def is_fresh(self, now: datetime | None = None) -> bool:
        return self.age(now) <= MAX_AGE


def cache_root() -> Path | None:
    """Return the shared cache directory, or ``None`` when it is not configured."""
    configured = os.environ.get(CACHE_DIR_ENV, "").strip()
    return Path(configured) if configured else None


def current_snapshot(root: Path | None = None) -> Snapshot | None:
    """Return the snapshot ``current`` points at, or ``None`` if unusable.

    The path is resolved once, so a refresh that swaps ``current`` does not
    affect a scan that already started.
    """
    root = root or cache_root()
    if root is None:
        return None
    link = root / CURRENT
    if not link.exists():
        return None
    path = Path(os.path.realpath(link))
    try:
        marker = json.loads((path / MARKER).read_text(encoding="utf-8"))
        refreshed_at = datetime.fromisoformat(marker["refreshed_at"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not (path / "db" / "trivy.db").is_file():
        return None
    java_db = bool(marker.get("java_db")) and (path / "java-db").is_dir()
    return Snapshot(path=path, refreshed_at=refreshed_at, java_db=java_db)


def scan_cache_env(work_dir: Path, *, root: Path | None = None) -> dict[str, str]:
    """Return the Trivy environment for one scan.

    Args:
        work_dir: The scan's temporary directory; its cache is created here.
        root: Shared cache directory (defaults to the configured one).

    Returns:
        ``TRIVY_CACHE_DIR`` and the skip-update flags when a fresh snapshot
        exists, otherwise an empty dict so Trivy downloads as before.
    """
    snapshot = current_snapshot(root)
    if snapshot is None or not snapshot.is_fresh():
        return {}
    cache = work_dir / "trivy-cache"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "db").symlink_to(snapshot.path / "db", target_is_directory=True)
    env = {"TRIVY_CACHE_DIR": str(cache), "TRIVY_SKIP_DB_UPDATE": "true"}
    if snapshot.java_db:
        (cache / "java-db").symlink_to(
            snapshot.path / "java-db", target_is_directory=True
        )
        env["TRIVY_SKIP_JAVA_DB_UPDATE"] = "true"
    return env


def _download(
    trivy_bin: str, cache_dir: Path, flag: str
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [trivy_bin, "--quiet", "image", "--cache-dir", str(cache_dir), flag],
        capture_output=True,
        text=True,
        timeout=REFRESH_TIMEOUT_SECONDS,
        check=False,
    )


def refresh(
    root: Path | None = None,
    *,
    trivy_bin: str | None = None,
    now: datetime | None = None,
) -> Snapshot:
    """Download both databases into a new snapshot and make it current.

    A failed Java database download keeps the snapshot; scans then let
    Trivy fetch the Java database themselves.

    Raises:
        VulnDbError: The cache is not configured or the download failed.
    """
    root = root or cache_root()
    if root is None:
        raise VulnDbError(f"{CACHE_DIR_ENV} is not set.")
    if trivy_bin is None:
        from cloudsneeker_api.services.trivy import _resolve_trivy_bin

        trivy_bin = _resolve_trivy_bin()
    now = now or datetime.now(UTC)

    name = f"{now:%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:6]}"
    snapshot = root / SNAPSHOTS / name
    snapshot.mkdir(parents=True)

    try:
        result = _download(trivy_bin, snapshot, "--download-db-only")
    except subprocess.TimeoutExpired:
        shutil.rmtree(snapshot, ignore_errors=True)
        raise VulnDbError("Vulnerability database download timed out.") from None
    if result.returncode != 0 or not (snapshot / "db" / "trivy.db").is_file():
        shutil.rmtree(snapshot, ignore_errors=True)
        detail = (result.stderr or "").strip().splitlines()[-1:] or ["no output"]
        raise VulnDbError(f"Vulnerability database download failed: {detail[0]}")

    try:
        java = _download(trivy_bin, snapshot, "--download-java-db-only")
        java_db = java.returncode == 0 and (snapshot / "java-db").is_dir()
    except subprocess.TimeoutExpired:
        java_db = False
    if not java_db:
        logger.warning("Java vulnerability database download failed; scans fetch it.")
        shutil.rmtree(snapshot / "java-db", ignore_errors=True)

    (snapshot / MARKER).write_text(
        json.dumps({"refreshed_at": now.isoformat(), "java_db": java_db}),
        encoding="utf-8",
    )

    # Swap atomically: a relative link renamed over ``current``.
    temp_link = root / f".{CURRENT}-{uuid.uuid4().hex[:6]}"
    temp_link.symlink_to(Path(SNAPSHOTS) / name, target_is_directory=True)
    os.replace(temp_link, root / CURRENT)

    prune(root)
    return Snapshot(path=snapshot, refreshed_at=now, java_db=java_db)


def prune(root: Path, keep: int = KEEP_SNAPSHOTS) -> list[str]:
    """Delete all but the newest ``keep`` snapshots; never the current one.

    With a 6-hour refresh, a snapshot is deleted at least 6 hours after it
    stopped being current, well past the longest scan.

    Returns:
        Names of the deleted snapshots.
    """
    snapshots_dir = root / SNAPSHOTS
    if not snapshots_dir.is_dir():
        return []
    current = current_snapshot(root)
    names = sorted(entry.name for entry in snapshots_dir.iterdir() if entry.is_dir())
    deleted = []
    for name in names[:-keep] if keep else names:
        path = snapshots_dir / name
        if current is not None and path.resolve() == current.path.resolve():
            continue
        shutil.rmtree(path, ignore_errors=True)
        deleted.append(name)
    return deleted
