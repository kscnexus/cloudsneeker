"""Fail when an upstream brand string can reach a client.

Usage::

    python cloudsneeker/tools/brand_audit.py --tree DIR        # transformed build tree
    python cloudsneeker/tools/brand_audit.py --artifacts DIR   # generated outputs (csv, json, html, pdf)
    python cloudsneeker/tools/brand_audit.py --source          # Cloudsneeker-owned source dirs

Exit code 1 when any forbidden pattern is found outside the allowlist.
"""

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib  # type: ignore[no-redef]

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent.parent
DEFAULT_ALLOW = TOOLS_DIR / "brand_audit.allow.toml"

sys.path.insert(0, str(REPO_ROOT))

from cloudsneeker.tools.pathmatch import matches_any, read_text, to_posix  # noqa: E402

FORBIDDEN = (
    re.compile(r"\bProwler\b"),
    re.compile(r"\bProwlerPro\b"),
    re.compile(r"prowler\.(?:com|pro|cloud)\b", re.IGNORECASE),
    re.compile(r"prowler-cloud\b", re.IGNORECASE),
    re.compile(r"prowlercloud\b", re.IGNORECASE),
    re.compile(r"hub\.prowler", re.IGNORECASE),
    re.compile(r"\bprowler-output-"),
    re.compile(r"\bprowler-ui\b|\bprowler-api\b|\bprowler-mcp\b"),
    # Security Hub ProductFields keys are rendered in the AWS console.
    re.compile(r"\bProwler(?:ResourceName|AccountOrganizationalUnit\w*)\b"),
)

SOURCE_DIRS = (
    "cloudsneeker",
    "api/src/backend/cloudsneeker_api",
    "ui/cloudsneeker",
    "ui/app/(cloudsneeker)",
)

SKIP_DIRS = {".git", "node_modules", ".venv", ".next", "__pycache__", "_data"}


@dataclass(frozen=True)
class Hit:
    """One forbidden match."""

    path: str
    line: int
    text: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.text.strip()[:160]}"


@dataclass(frozen=True)
class Allowlist:
    """Paths and patterns that the audit skips."""

    paths: tuple[str, ...]
    patterns: tuple[re.Pattern[str], ...]


def load_allowlist(path: Path) -> Allowlist:
    """Parse the TOML allowlist.

    Args:
        path: Allowlist file.

    Returns:
        Parsed allowlist.
    """
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return Allowlist(
        paths=tuple(data.get("paths", {}).get("allow", [])),
        patterns=tuple(
            re.compile(p) for p in data.get("patterns", {}).get("allow", [])
        ),
    )


def _mask(line: str, allowlist: Allowlist) -> str:
    for pattern in allowlist.patterns:
        line = pattern.sub(lambda m: " " * len(m.group(0)), line)
    return line


def scan_text(path_label: str, text: str, allowlist: Allowlist) -> list[Hit]:
    """Find forbidden strings in one text blob.

    Args:
        path_label: Label used in the report.
        text: Content to scan.
        allowlist: Patterns to mask before matching.

    Returns:
        Hits in line order.
    """
    hits: list[Hit] = []
    for number, line in enumerate(text.splitlines(), start=1):
        masked = _mask(line, allowlist)
        if any(pattern.search(masked) for pattern in FORBIDDEN):
            hits.append(Hit(path=path_label, line=number, text=line))
    return hits


def _pdf_text(path: Path) -> str | None:
    try:
        from pypdf import PdfReader  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        return None
    try:
        reader = PdfReader(str(path))
    except Exception:  # pragma: no cover - corrupt input
        return None
    parts = [page.extract_text() or "" for page in reader.pages]
    meta = reader.metadata or {}
    parts.extend(str(value) for value in meta.values())
    return "\n".join(parts)


def iter_files(root: Path):
    """Yield files under ``root`` skipping heavyweight directories."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for filename in filenames:
            yield Path(dirpath) / filename


def audit_tree(
    root: Path, allowlist: Allowlist, use_allow_paths: bool = True
) -> list[Hit]:
    """Audit every text file in a tree.

    Args:
        root: Directory to scan.
        allowlist: Paths and patterns to ignore.
        use_allow_paths: Apply the path allowlist. Artifacts directories set this
            to False so every generated file is checked.

    Returns:
        All hits.
    """
    hits: list[Hit] = []
    for path in iter_files(root):
        relative = to_posix(path, root)
        if use_allow_paths and matches_any(relative, allowlist.paths):
            continue
        if path.suffix.lower() == ".pdf":
            text = _pdf_text(path)
        else:
            text = read_text(path)
        if text is None:
            continue
        hits.extend(scan_text(relative, text, allowlist))
    return hits


def audit_source(repo_root: Path, allowlist: Allowlist) -> list[Hit]:
    """Audit the Cloudsneeker-owned directories of the repository.

    Args:
        repo_root: Repository root.
        allowlist: Paths and patterns to ignore.

    Returns:
        All hits.
    """
    hits: list[Hit] = []
    for name in SOURCE_DIRS:
        directory = repo_root / name
        if not directory.exists():
            continue
        for path in iter_files(directory):
            relative = to_posix(path, repo_root)
            if matches_any(relative, allowlist.paths):
                continue
            text = read_text(path)
            if text is None:
                continue
            hits.extend(scan_text(relative, text, allowlist))
    return hits


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point.

    Args:
        argv: Arguments without the program name.

    Returns:
        Process exit code.
    """
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--tree", type=Path, help="transformed build tree to audit")
    mode.add_argument("--artifacts", type=Path, help="directory of generated outputs")
    mode.add_argument(
        "--source", action="store_true", help="audit Cloudsneeker-owned dirs"
    )
    parser.add_argument("--allow", type=Path, default=DEFAULT_ALLOW)
    parser.add_argument("--max-print", type=int, default=200)
    args = parser.parse_args(argv)

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    allowlist = load_allowlist(args.allow)
    if args.source:
        hits = audit_source(REPO_ROOT, allowlist)
    elif args.tree is not None:
        hits = audit_tree(args.tree.resolve(), allowlist)
    else:
        hits = audit_tree(args.artifacts.resolve(), allowlist, use_allow_paths=False)

    for hit in hits[: args.max_print]:
        print(hit)
    if len(hits) > args.max_print:
        print(f"... {len(hits) - args.max_print} more")
    print(f"brand audit: {len(hits)} hit(s)")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
