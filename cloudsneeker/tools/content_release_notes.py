"""Generate the detection content release notes shown in the app (EB-049).

Each release lists the posture checks and compliance frameworks that were
added, changed or removed since the previous upstream release. The notes are
built by diffing the check metadata and compliance JSON of consecutive upstream
tags; the newest release is diffed against the working tree, which is what the
images ship. The result is written to ``cloudsneeker/content/releases.json``,
which the API serves.

Run after merging an upstream tag (``sync-upstream.ps1`` does this)::

    python cloudsneeker/tools/content_release_notes.py

``tests/cloudsneeker/content_releases_test.py`` fails while the committed notes
do not match the tree. Needs the upstream tags (``git fetch upstream --tags``).

Titles and names pass through the build-time rebrand rules, so the notes read
like the rest of the shipped content. Depends only on the standard library.
"""

import argparse
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
from functools import cache
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cloudsneeker.brand import load_brand  # noqa: E402
from cloudsneeker.tools import rebrand  # noqa: E402

OUTPUT = ROOT / "cloudsneeker" / "content" / "releases.json"
DEFAULT_SINCE = "5.38.0"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
CHECK_PATH_RE = re.compile(
    r"^prowler/providers/([^/]+)/services/([^/]+)/([^/]+)/\3\.metadata\.json$"
)
FRAMEWORK_PATH_RE = re.compile(r"^prowler/compliance/(.+)\.json$")
GIT_PATHSPEC = (
    ":(glob)prowler/providers/*/services/*/*/*.metadata.json",
    ":(glob)prowler/compliance/**/*.json",
)

# Metadata fields whose change is reported, by their label in the notes.
CHECK_FIELDS = {
    "title": "CheckTitle",
    "severity": "Severity",
    "description": "Description",
    "risk": "Risk",
    "remediation": "Remediation",
    "categories": "Categories",
}


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _check_entry(provider: str, service: str, metadata: dict) -> dict:
    fields = {label: metadata.get(key) for label, key in CHECK_FIELDS.items()}
    return {
        "provider": metadata.get("Provider") or provider,
        "service": metadata.get("ServiceName") or service,
        **fields,
    }


def _field(document: dict, name: str):
    """Provider frameworks use ``Name``; universal frameworks use ``name``."""
    return document.get(name, document.get(name.lower()))


def _framework_entry(path: str, document: dict) -> dict:
    requirements = {}
    for requirement in _field(document, "Requirements") or []:
        checks = _field(requirement, "Checks") or []
        if isinstance(checks, dict):
            # Universal frameworks map checks per provider.
            checks = [
                f"{provider}/{check}"
                for provider, values in checks.items()
                for check in values
            ]
        requirements[str(_field(requirement, "Id"))] = sorted(set(checks))
    provider = _field(document, "Provider") or (
        path.split("/")[0] if "/" in path else "multi-cloud"
    )
    return {
        "name": _field(document, "Name") or _field(document, "Framework") or path,
        "framework": _field(document, "Framework"),
        "version": _field(document, "Version"),
        "provider": str(provider).lower(),
        "requirements": requirements,
    }


@cache
def _rebrand_rules() -> rebrand.RuleSet:
    # Default brand values, so the notes do not depend on the environment.
    return rebrand.load_rules(rebrand.DEFAULT_RULES, load_brand({}))


def _rebranded(path: str, data: bytes) -> str:
    text = data.decode("utf-8")
    rules = rebrand.rules_for(path, _rebrand_rules())
    return rebrand.transform_text(text, rules)[0] if rules else text


def catalog_from_files(files) -> dict:
    """Build a catalog from ``(posix path, bytes)`` pairs relative to the repo."""
    checks: dict[str, dict] = {}
    frameworks: dict[str, dict] = {}
    for path, data in files:
        check = CHECK_PATH_RE.match(path)
        framework = FRAMEWORK_PATH_RE.match(path)
        if not check and not framework:
            continue
        try:
            document = json.loads(_rebranded(path, data))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(document, dict):
            continue
        if check:
            provider, service, check_id = check.groups()
            checks[check_id] = _check_entry(provider, service, document)
        else:
            key = framework.group(1)
            frameworks[key] = _framework_entry(key, document)
    return {"checks": checks, "frameworks": frameworks}


def catalog_from_tree(root: Path = ROOT) -> dict:
    """Catalog of the checks and frameworks in a source tree."""
    paths = list(
        (root / "prowler" / "providers").glob("*/services/*/*/*.metadata.json")
    )
    paths += (root / "prowler" / "compliance").rglob("*.json")
    return catalog_from_files(
        (PurePosixPath(path.relative_to(root)).as_posix(), path.read_bytes())
        for path in paths
    )


def catalog_from_git(ref: str, root: Path = ROOT) -> dict:
    """Catalog of the checks and frameworks at a git ref."""
    archive = subprocess.run(
        ["git", "archive", "--format=tar", ref, "--", *GIT_PATHSPEC],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        return catalog_from_files(
            (member.name, tar.extractfile(member).read())
            for member in tar.getmembers()
            if member.isfile()
        )


def catalog_digest(catalog: dict) -> str:
    canonical = json.dumps(catalog, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _check_summary(check_id: str, entry: dict) -> dict:
    return {
        "id": check_id,
        "provider": entry["provider"],
        "service": entry["service"],
        "title": entry["title"],
        "severity": entry["severity"],
    }


def _framework_summary(key: str, entry: dict) -> dict:
    return {
        "id": key,
        "name": entry["name"],
        "provider": entry["provider"],
        "version": entry["version"],
        "requirements": len(entry["requirements"]),
    }


def _framework_changes(old: dict, new: dict) -> dict | None:
    fields = [field for field in ("name", "version") if old[field] != new[field]]
    old_ids, new_ids = set(old["requirements"]), set(new["requirements"])
    remapped = sum(
        1
        for requirement in old_ids & new_ids
        if old["requirements"][requirement] != new["requirements"][requirement]
    )
    changes = {
        "fields": fields,
        "requirements_added": len(new_ids - old_ids),
        "requirements_removed": len(old_ids - new_ids),
        "requirements_remapped": remapped,
    }
    if not fields and not any(
        value for key, value in changes.items() if key != "fields"
    ):
        return None
    return changes


def diff_catalogs(old: dict, new: dict) -> dict:
    """Added, changed and removed checks and frameworks between two catalogs."""
    old_checks, new_checks = old["checks"], new["checks"]
    checks = {
        "added": [
            _check_summary(check_id, new_checks[check_id])
            for check_id in sorted(new_checks.keys() - old_checks.keys())
        ],
        "changed": [],
        "removed": [
            _check_summary(check_id, old_checks[check_id])
            for check_id in sorted(old_checks.keys() - new_checks.keys())
        ],
    }
    for check_id in sorted(old_checks.keys() & new_checks.keys()):
        fields = [
            label
            for label in CHECK_FIELDS
            if old_checks[check_id][label] != new_checks[check_id][label]
        ]
        if fields:
            checks["changed"].append(
                {**_check_summary(check_id, new_checks[check_id]), "fields": fields}
            )

    old_frameworks, new_frameworks = old["frameworks"], new["frameworks"]
    frameworks = {
        "added": [
            _framework_summary(key, new_frameworks[key])
            for key in sorted(new_frameworks.keys() - old_frameworks.keys())
        ],
        "changed": [],
        "removed": [
            _framework_summary(key, old_frameworks[key])
            for key in sorted(old_frameworks.keys() - new_frameworks.keys())
        ],
    }
    for key in sorted(old_frameworks.keys() & new_frameworks.keys()):
        changes = _framework_changes(old_frameworks[key], new_frameworks[key])
        if changes:
            frameworks["changed"].append(
                {**_framework_summary(key, new_frameworks[key]), **changes}
            )
    return {"checks": checks, "frameworks": frameworks}


def _git(*args: str, root: Path = ROOT) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()


def release_tags(root: Path = ROOT) -> list[str]:
    tags = [
        tag
        for tag in _git("tag", "--list", root=root).splitlines()
        if VERSION_RE.match(tag)
    ]
    return sorted(tags, key=_version_key)


def tree_version(root: Path = ROOT) -> str:
    config = (root / "prowler" / "config" / "config.py").read_text(encoding="utf-8")
    return re.search(r'^prowler_version = "([^"]+)"', config, re.MULTILINE).group(1)


def _release(version: str, previous: str, diff: dict, released_at: str | None) -> dict:
    return {
        "version": version,
        "current": released_at is None,
        "previous_version": previous,
        "released_at": released_at,
        "summary": {
            f"{kind}_{change}": len(diff[kind][change])
            for kind in ("checks", "frameworks")
            for change in ("added", "changed", "removed")
        },
        **diff,
    }


def generate(since: str = DEFAULT_SINCE, root: Path = ROOT) -> dict:
    """Release notes from ``since`` up to the version in the working tree."""
    current = tree_version(root)
    tags = release_tags(root)
    if since not in tags:
        raise SystemExit(f"Tag {since} not found; run: git fetch upstream --tags")
    earlier = [tag for tag in tags if _version_key(tag) < _version_key(since)]
    if not earlier:
        raise SystemExit(f"No upstream tag before {since} to diff against")
    versions = [
        tag
        for tag in tags
        if _version_key(since) <= _version_key(tag) < _version_key(current)
    ] + [current]

    releases = []
    previous = earlier[-1]
    old = catalog_from_git(previous, root)
    for version in versions:
        new = (
            catalog_from_tree(root)
            if version == current
            else catalog_from_git(version, root)
        )
        # The tree follows upstream's main branch, so the current version may
        # carry a tag name without matching that tag; it has no release date.
        released_at = (
            None
            if version == current
            else _git("log", "-1", "--format=%cI", version, root=root)
        )
        releases.append(
            _release(version, previous, diff_catalogs(old, new), released_at)
        )
        previous, old = version, new
    releases.reverse()
    return {"since": since, "catalog_digest": catalog_digest(old), "releases": releases}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--since",
        help=f"oldest release to include (default: the committed notes' since, or {DEFAULT_SINCE})",
    )
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    since = args.since
    if not since and args.output.exists():
        since = json.loads(args.output.read_text(encoding="utf-8")).get("since")
    notes = generate(since or DEFAULT_SINCE)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(notes, indent=1, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    for release in notes["releases"]:
        print(release["version"], release["summary"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
