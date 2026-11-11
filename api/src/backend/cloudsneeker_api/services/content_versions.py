"""Detection content and engine versions for the Settings panel (EB-048).

Customers and auditors use this to see how current detection is: the posture
content release with its check and framework counts, the vulnerability
database age, the code analysis rules and the bundled engine versions.
Engine names stay out of the response; each entry carries a product label.

Versions come from the image (``ENV`` lines in the Dockerfiles and installed
packages). The vulnerability database state is read from the shared cache
(``CLOUDSNEEKER_VULN_DB_CACHE_DIR``), which the API mounts read-only.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from functools import lru_cache
from importlib import metadata
from pathlib import Path

from cloudsneeker_api.services import vuln_db, vuln_intel

RELEASE_ENV = "CLOUDSNEEKER_RELEASE_VERSION"
SAST_RULES_REF_ENV = "CLOUDSNEEKER_SAST_RULES_REF"
RULES_DIR_ENV = "OPENGREP_RULES_DIR"

# (id, label, environment variable or package) for each bundled engine.
ENGINE_ENV = (
    ("scanner", "Vulnerability and IaC scanner", "TRIVY_VERSION"),
    ("code_analyzer", "Code analyzer", "CLOUDSNEEKER_OPENGREP_VERSION"),
    ("governance", "Governance engine", "CLOUDSNEEKER_C7N_VERSION"),
    ("workflow_scanner", "CI workflow scanner", "ZIZMOR_VERSION"),
)
ENGINE_PACKAGES = (("attack_paths", "Attack paths graph", "cartography"),)

STATUS_FRESH = "fresh"
STATUS_STALE = "stale"
STATUS_MISSING = "missing"
STATUS_NOT_CONFIGURED = "not_configured"

# Trivy writes nanoseconds; ``fromisoformat`` takes at most microseconds.
_FRACTION = re.compile(r"(\.\d{6})\d+")


def _parse_time(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(
            _FRACTION.sub(r"\1", value.replace("Z", "+00:00"))
        )
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value else None


def _published_at(db_dir: Path) -> datetime | None:
    """When the database publisher built this copy (``UpdatedAt``)."""
    try:
        data = json.loads((db_dir / "metadata.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return _parse_time(data.get("UpdatedAt")) if isinstance(data, dict) else None


def vulnerability_database(now: datetime | None = None) -> dict:
    """State of the shared CVE database snapshot.

    ``status`` is ``fresh`` (scans use it), ``stale`` (older than the
    24-hour limit, so scans download their own copy), ``missing`` (no usable
    snapshot yet) or ``not_configured`` (no shared cache on this deployment).
    """
    now = now or datetime.now(UTC)
    result = {
        "status": STATUS_NOT_CONFIGURED,
        "refreshed_at": None,
        "published_at": None,
        "age_hours": None,
        "max_age_hours": int(vuln_db.MAX_AGE.total_seconds() // 3600),
        "java_db": False,
    }
    root = vuln_db.cache_root()
    if root is None:
        return result
    snapshot = vuln_db.current_snapshot(root)
    if snapshot is None:
        result["status"] = STATUS_MISSING
        return result
    age = snapshot.age(now)
    result.update(
        status=STATUS_FRESH if snapshot.is_fresh(now) else STATUS_STALE,
        refreshed_at=_iso(snapshot.refreshed_at),
        published_at=_iso(_published_at(snapshot.path / "db")),
        age_hours=round(age.total_seconds() / 3600, 1),
        java_db=snapshot.java_db,
    )
    return result


@lru_cache(maxsize=1)
def _posture_counts() -> tuple[int, int]:
    """Number of posture checks and compliance frameworks in the image."""
    import prowler

    package = Path(prowler.__file__).resolve().parent
    checks = sum(1 for _ in package.glob("providers/*/services/*/*/*.metadata.json"))
    frameworks = sum(1 for _ in package.glob("compliance/**/*.json"))
    return checks, frameworks


def cloud_security_content() -> dict:
    from prowler.config.config import prowler_version

    checks, frameworks = _posture_counts()
    return {"version": prowler_version, "checks": checks, "frameworks": frameworks}


@lru_cache(maxsize=1)
def _rule_count(rules_dir: str) -> int | None:
    path = Path(rules_dir)
    if not path.is_dir():
        return None
    return sum(1 for entry in path.rglob("*") if entry.suffix in {".yml", ".yaml"})


def code_analysis_rules() -> dict:
    rules_dir = os.environ.get(RULES_DIR_ENV, "").strip()
    return {
        "version": os.environ.get(SAST_RULES_REF_ENV, "").strip() or None,
        "rules": _rule_count(rules_dir) if rules_dir else None,
    }


def _package_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def engines() -> list[dict]:
    entries = [
        {"id": key, "label": label, "version": os.environ.get(env, "").strip() or None}
        for key, label, env in ENGINE_ENV
    ]
    entries += [
        {"id": key, "label": label, "version": _package_version(package)}
        for key, label, package in ENGINE_PACKAGES
    ]
    return entries


def exploit_intelligence() -> list[dict]:
    """EPSS and CISA KEV feeds: data version, CVE count and last refresh."""
    return [
        {**feed, "refreshed_at": _iso(feed["refreshed_at"])}
        for feed in vuln_intel.feed_status()
    ]


def content_versions(now: datetime | None = None) -> dict:
    """Attributes of the ``content-versions`` resource."""
    return {
        "release": os.environ.get(RELEASE_ENV, "").strip() or None,
        "cloud_security": cloud_security_content(),
        "vulnerability_database": vulnerability_database(now),
        "code_analysis_rules": code_analysis_rules(),
        "exploit_intelligence": exploit_intelligence(),
        "engines": engines(),
    }
