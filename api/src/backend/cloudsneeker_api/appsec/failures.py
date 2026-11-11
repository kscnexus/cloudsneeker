"""Scan process outcome classification.

The engine exits 0 when the scan ran, whatever it found (no ``--exit-code``
is passed), and non-zero on a fatal error. The reason is only in stderr, so
it is matched against known messages to decide whether a retry can help and
what to tell the user.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

FAILURE_DATABASE = "database"
FAILURE_TIMEOUT = "timeout"
FAILURE_AUTH = "auth"
FAILURE_NOT_FOUND = "not_found"
FAILURE_NETWORK = "network"
FAILURE_INPUT = "input"
FAILURE_RESOURCES = "resources"
FAILURE_OUTPUT = "output"
FAILURE_CANCELLED = "cancelled"
FAILURE_ENGINE = "engine"

STDERR_TAIL_CHARS = 4000

_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    (
        FAILURE_DATABASE,
        re.compile(
            r"(failed to download (vulnerability|java) ?db|db download error|"
            r"failed to download artifact|init error: db error|"
            r"unable to (initialize|download) .*(db|database)|"
            r"oci download error|TOOMANYREQUESTS|checks? bundle)",
            re.IGNORECASE,
        ),
    ),
    (
        FAILURE_TIMEOUT,
        re.compile(
            r"(context deadline exceeded|timeout exceeded|timed out)", re.IGNORECASE
        ),
    ),
    (
        FAILURE_AUTH,
        re.compile(
            r"(UNAUTHORIZED|authentication (required|failed)|401 Unauthorized|"
            r"403 Forbidden|DENIED|invalid username or password|"
            r"could not read Username|Permission denied \(publickey\))",
            re.IGNORECASE,
        ),
    ),
    (
        FAILURE_NOT_FOUND,
        re.compile(
            r"(MANIFEST_UNKNOWN|NAME_UNKNOWN|repository not found|"
            r"reference not found|couldn't find remote ref|no such image|"
            r"unable to find the specified image)",
            re.IGNORECASE,
        ),
    ),
    (
        FAILURE_RESOURCES,
        re.compile(
            r"(no space left on device|cannot allocate memory|out of memory|"
            r"signal: killed)",
            re.IGNORECASE,
        ),
    ),
    (
        FAILURE_NETWORK,
        re.compile(
            r"(no such host|connection refused|connection reset|i/o timeout|"
            r"TLS handshake|network is unreachable|dial tcp)",
            re.IGNORECASE,
        ),
    ),
    (
        FAILURE_INPUT,
        re.compile(
            r"(unsupported sbom format|failed to (decode|unmarshal|parse)|"
            r"invalid (argument|reference)|unknown flag|"
            r"kubeconfig|no such file or directory)",
            re.IGNORECASE,
        ),
    ),
)

_MESSAGES = {
    FAILURE_DATABASE: "The vulnerability database could not be downloaded.",
    FAILURE_TIMEOUT: "The scan did not finish within its time limit.",
    FAILURE_AUTH: "The source rejected the stored credentials.",
    FAILURE_NOT_FOUND: "The repository, reference or image was not found.",
    FAILURE_NETWORK: "The source could not be reached over the network.",
    FAILURE_INPUT: "The scan input could not be read.",
    FAILURE_RESOURCES: "The worker ran out of memory or disk space.",
    FAILURE_OUTPUT: "The scanner returned a report that could not be read.",
    FAILURE_CANCELLED: "The scan was cancelled.",
    FAILURE_ENGINE: "The scanner stopped with an error.",
}

RETRYABLE = frozenset({FAILURE_DATABASE, FAILURE_NETWORK})

_LOG_PREFIX_RE = re.compile(r"^\S+\s+(FATAL|ERROR)\s+", re.IGNORECASE)


@dataclass(frozen=True)
class Failure:
    kind: str
    message: str
    retryable: bool


def stderr_tail(stderr: str | None, limit: int = STDERR_TAIL_CHARS) -> str:
    """Last ``limit`` characters of stderr, cut at a line start."""
    text = (stderr or "").strip()
    if len(text) <= limit:
        return text
    tail = text[-limit:]
    newline = tail.find("\n")
    return tail[newline + 1 :] if 0 <= newline < len(tail) - 1 else tail


def last_error_line(stderr: str | None) -> str:
    """The last FATAL or ERROR log line, without timestamp and level."""
    lines = [line.strip() for line in (stderr or "").splitlines() if line.strip()]
    for line in reversed(lines):
        if re.search(r"\b(FATAL|ERROR)\b", line):
            return _LOG_PREFIX_RE.sub("", line)[:500]
    return lines[-1][:500] if lines else ""


def classify_failure(exit_code: int | None, stderr: str | None) -> Failure:
    """Classify a failed scan process.

    Args:
        exit_code: Process exit status (``None`` when it was killed).
        stderr: Captured standard error.

    Returns:
        The failure kind, a user-facing message and whether to retry.
    """
    text = stderr or ""
    kind = FAILURE_ENGINE
    for candidate, pattern in _PATTERNS:
        if pattern.search(text):
            kind = candidate
            break
    detail = last_error_line(text)
    message = _MESSAGES[kind]
    if detail:
        message = f"{message} {detail}"
    elif exit_code is not None:
        message = f"{message} (exit status {exit_code})"
    return Failure(kind=kind, message=message, retryable=kind in RETRYABLE)


def failure(kind: str, detail: str = "") -> Failure:
    """Build a failure of a known kind."""
    message = _MESSAGES.get(kind, _MESSAGES[FAILURE_ENGINE])
    if detail:
        message = f"{message} {detail}"
    return Failure(kind=kind, message=message, retryable=kind in RETRYABLE)


def retry_delay_seconds(attempt: int, base: int = 15, cap: int = 120) -> int:
    """Backoff before retry number ``attempt`` (1 for the first retry)."""
    return min(cap, base * (2 ** max(0, attempt - 1)))
