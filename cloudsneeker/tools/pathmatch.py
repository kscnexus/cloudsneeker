"""Glob matching shared by the rebrand and audit tools.

Patterns use ``/`` separators and support ``**`` for any number of directories,
``*`` for any run of characters inside one path segment, and ``?`` for a single
character. A pattern without ``/`` matches a file name at any depth.
"""

import re
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=None)
def compile_glob(pattern: str) -> re.Pattern[str]:
    """Translate a glob into an anchored regular expression.

    Args:
        pattern: Glob pattern using ``/`` separators.

    Returns:
        Compiled regular expression matching a POSIX-style relative path.
    """
    if "/" not in pattern:
        pattern = f"**/{pattern}"
    out = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif char == "*":
            out.append("[^/]*")
            i += 1
        elif char == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(char))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def matches_any(relative_path: str, patterns: tuple[str, ...] | list[str]) -> bool:
    """Return True when the path matches at least one glob.

    Args:
        relative_path: Path relative to the scanned root, POSIX separators.
        patterns: Glob patterns.

    Returns:
        Whether any pattern matches.
    """
    return any(compile_glob(pattern).match(relative_path) for pattern in patterns)


def to_posix(path: Path, root: Path) -> str:
    """Return ``path`` relative to ``root`` with ``/`` separators.

    Args:
        path: Absolute or relative file path.
        root: Root the result is relative to.

    Returns:
        Relative POSIX path string.
    """
    return path.relative_to(root).as_posix()


def read_text(path: Path) -> str | None:
    """Read a UTF-8 text file, returning None for binary or undecodable files.

    Args:
        path: File to read.

    Returns:
        File contents or None.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8000]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None
