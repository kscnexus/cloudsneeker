"""Keep scanner engine names and internals out of user-facing text.

Run errors and validation messages often carry the raw output of the bundled
engines (log prefixes such as ``custodian.commands:ERROR``, temporary file
paths, engine names). The product presents one platform, so this module
rewrites that text before it reaches the API response or the database.
"""

from __future__ import annotations

import re

# "2026-10-27 18:29:58,918: " at the start of a line.
_TIMESTAMP_PREFIX = re.compile(
    r"^\s*\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?:?\s*", re.MULTILINE
)
# Logger names such as "custodian.commands:ERROR " or "c7n.policy:WARNING ".
_LOGGER_PREFIX = re.compile(
    r"\b(?:custodian|c7n|trivy|opengrep|semgrep)[\w.]*:"
    r"(?:ERROR|WARNING|WARN|INFO|DEBUG|CRITICAL|FATAL)\b:?\s*",
    re.IGNORECASE,
)
# Temporary working files, e.g. "/tmp/cs-custodian-4_46uj8g/policy.yml".
_TEMP_PATH = re.compile(r"(?:/tmp|/var/tmp)/[^\s:'\"]*?([\w.-]+\.(?:ya?ml|json))\b")
_TEMP_DIR = re.compile(r"(?:/tmp|/var/tmp)/[^\s:'\"]+")

# Ordered: longer phrases first so "Cloud Custodian" is not rewritten twice.
_ENGINE_NAMES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bCloud Custodian\b", re.IGNORECASE), "Cloud Governance"),
    (re.compile(r"\bTrivy Hub\b", re.IGNORECASE), "Application Security"),
    (re.compile(r"\bc7n(?:[-_]\w+)?\b"), "governance"),
    (re.compile(r"\bCustodian\b"), "governance engine"),
    (re.compile(r"\bcustodian\b"), "governance engine"),
    (re.compile(r"\bTrivy\b"), "scanner"),
    (re.compile(r"\btrivy\b"), "scanner"),
    (re.compile(r"\b(?:OpenGrep|Opengrep|opengrep|Semgrep|semgrep)\b"), "code analyzer"),
)


def scrub_engine_text(text: str | None) -> str:
    """Return ``text`` without engine names, logger prefixes, or temp paths."""
    if not text:
        return text or ""
    original = str(text)
    cleaned = _LOGGER_PREFIX.sub("", _TIMESTAMP_PREFIX.sub("", original))
    stripped_prefix = cleaned != original
    cleaned = _TEMP_PATH.sub(r"\1", cleaned)
    cleaned = _TEMP_DIR.sub("a temporary file", cleaned)
    for pattern, replacement in _ENGINE_NAMES:
        cleaned = pattern.sub(replacement, cleaned)
    cleaned = cleaned.strip()
    if stripped_prefix:
        # The message now starts mid-sentence ("invalid policy file: ...").
        cleaned = cleaned[:1].upper() + cleaned[1:]
    return cleaned
