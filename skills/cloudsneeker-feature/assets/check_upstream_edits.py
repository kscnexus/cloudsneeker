"""List modified upstream files on this branch that upstream-hooks.md does not record.

A Cloudsneeker change may add files anywhere, but it may only modify an
inherited file through a recorded hook. This script compares the branch (and
the working tree) with a base ref and prints every modified file that is
neither Cloudsneeker-owned nor named in ``knowledge-base/upstream-hooks.md``.

Limits: a file that already has a row passes for any further edit, and on an
upstream-merge branch every file upstream changed is reported.

Usage:
    python skills/cloudsneeker-feature/assets/check_upstream_edits.py [--base REF]

Exit code is 1 when at least one unrecorded edit is found, 2 on a git error.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
HOOKS_DOC = REPO_ROOT / "knowledge-base" / "upstream-hooks.md"
DEFAULT_BASES = ("github/main", "origin/main", "main")

OWNED_PREFIXES = (
    "cloudsneeker/",
    "api/src/backend/cloudsneeker_api/",
    "ui/app/(cloudsneeker)/",
    "ui/app/(cloudsneeker-public)/",
    "ui/cloudsneeker/",
    "mcp_server/prowler_mcp_server/cloudsneeker/",
    "tests/cloudsneeker/",
    "knowledge-base/",
    "website/",
    "skills/cloudsneeker-",
    ".github/workflows/cloudsneeker-",
)


def git(*args: str) -> str:
    """Run a git command in the repository and return its output."""
    result = subprocess.run(
        ["git", "-c", "core.quotepath=off", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout


def resolve_base(requested: str | None) -> str:
    """Return the first base ref that exists."""
    candidates = (requested,) if requested else DEFAULT_BASES
    for ref in candidates:
        try:
            git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
        except RuntimeError:
            continue
        return ref
    raise RuntimeError(f"no base ref found (tried: {', '.join(candidates)})")


def modified_files(base: str) -> set[str]:
    """Return files modified or deleted (not added) on the branch or working tree."""
    merge_base = git("merge-base", base, "HEAD").strip()
    output = git("diff", "--name-status", "--diff-filter=MRTD", merge_base)
    files = set()
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            files.add(parts[-1])
    return files


def is_owned(path: str) -> bool:
    """Return True for a path inside a Cloudsneeker-owned directory."""
    return path.startswith(OWNED_PREFIXES)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", help="ref to compare with (default: github/main)")
    args = parser.parse_args()

    try:
        base = resolve_base(args.base)
        changed = modified_files(base)
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    recorded = HOOKS_DOC.read_text(encoding="utf-8")
    unrecorded = sorted(
        path
        for path in changed
        if not is_owned(path) and f"`{path}`" not in recorded
    )

    if not unrecorded:
        print(f"OK: no unrecorded upstream edits against {base}.")
        return 0

    print(f"Modified upstream files not recorded in {HOOKS_DOC.name} (base {base}):")
    for path in unrecorded:
        print(f"  {path}")
    print(
        "\nMove the behavior into a Cloudsneeker directory, or mark the line with"
        " `cloudsneeker-hook` and add a row for the file to the hooks document."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
