"""How to fix a finding, read from what the scanner stored with it.

Application Security results keep the scanner's own record in
``Finding.raw_result`` (Trivy vulnerability, misconfiguration, secret or
license; Semgrep result). Cloud checks carry ``Remediation`` in their check
metadata. This module turns either into one shape the area findings list
returns:

* ``fix_available``: a concrete fix exists (a fixed package version, a
  resolution, a code fix, or a recommendation from the check);
* ``fix_summary``: one or two sentences saying what to do;
* ``installed_version`` / ``fixed_version``: for package vulnerabilities;
* ``fix_references``: up to five advisory or documentation links.

Read at request time, so findings stored before this existed get fixes too.
"""

from __future__ import annotations

from typing import Any

MAX_REFERENCES = 5

# Ways to get to "fix available" for one finding, also used as the list filter.
FIX_AVAILABLE = "available"
FIX_UNAVAILABLE = "unavailable"
FIX_FILTER_VALUES = (FIX_AVAILABLE, FIX_UNAVAILABLE)


def _value(data: Any, key: str) -> Any:
    """``data[key]``, matching the key without regard to case."""
    if not isinstance(data, dict):
        return None
    if key in data:
        return data[key]
    wanted = key.lower()
    for name, value in data.items():
        if isinstance(name, str) and name.lower() == wanted:
            return value
    return None


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _urls(*candidates: Any) -> list[str]:
    urls: list[str] = []
    for candidate in candidates:
        items = candidate if isinstance(candidate, list) else [candidate]
        for item in items:
            url = _text(item)
            if url.startswith(("https://", "http://")) and url not in urls:
                urls.append(url)
            if len(urls) >= MAX_REFERENCES:
                return urls
    return urls


def _recommendation(metadata: Any) -> tuple[str, str]:
    """Check metadata ``Remediation.Recommendation`` text and URL."""
    recommendation = _value(_value(metadata, "Remediation"), "Recommendation")
    return _text(_value(recommendation, "Text")), _text(_value(recommendation, "Url"))


def _package_fix(raw: dict[str, Any]) -> dict[str, Any] | None:
    package = _text(raw.get("PkgName")) or _text(raw.get("PkgID"))
    if not package or "VulnerabilityID" not in raw and "InstalledVersion" not in raw:
        return None
    installed = _text(raw.get("InstalledVersion"))
    fixed = _text(raw.get("FixedVersion"))
    if fixed:
        summary = (
            f"Upgrade {package} from {installed} to {fixed} or later."
            if installed
            else f"Upgrade {package} to {fixed} or later."
        )
    else:
        summary = (
            f"No fixed version of {package} is published yet. Check whether the "
            "vulnerable code path is used, limit exposure, or replace the package."
        )
    return {
        "fix_available": bool(fixed),
        "fix_summary": summary,
        "installed_version": installed,
        "fixed_version": fixed,
        "fix_references": _urls(raw.get("PrimaryURL"), raw.get("References")),
    }


def _secret_fix(raw: dict[str, Any]) -> dict[str, Any] | None:
    if "RuleID" not in raw or "Match" not in raw:
        return None
    line = raw.get("StartLine")
    where = f" (line {line})" if line else ""
    return {
        "fix_available": True,
        "fix_summary": (
            f"Revoke and rotate this {_text(raw.get('Category')) or 'credential'}, "
            f"then remove it from the code{where} and its git history. Load it "
            "from a secret manager or environment variable instead."
        ),
        "installed_version": "",
        "fixed_version": "",
        "fix_references": [],
    }


def _license_fix(raw: dict[str, Any]) -> dict[str, Any] | None:
    if "Category" not in raw or "Name" not in raw or "RuleID" in raw:
        return None
    package = _text(raw.get("PkgName")) or "this package"
    return {
        "fix_available": True,
        "fix_summary": (
            f"Confirm the {_text(raw.get('Name'))} license of {package} is allowed "
            "for how you ship this code, or replace the package."
        ),
        "installed_version": "",
        "fixed_version": "",
        "fix_references": _urls(raw.get("Link")),
    }


def _misconfiguration_fix(raw: dict[str, Any]) -> dict[str, Any] | None:
    resolution = _text(raw.get("Resolution"))
    if not resolution:
        return None
    return {
        "fix_available": True,
        "fix_summary": resolution,
        "installed_version": "",
        "fixed_version": "",
        "fix_references": _urls(raw.get("PrimaryURL"), raw.get("References")),
    }


def _semgrep_fix(raw: dict[str, Any]) -> dict[str, Any] | None:
    extra = raw.get("extra")
    if not isinstance(extra, dict):
        return None
    code_fix = _text(extra.get("fix"))
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    message = _text(extra.get("message"))
    if code_fix:
        summary = f"Replace the flagged code with: {code_fix}"
    elif message:
        summary = message
    else:
        return None
    return {
        "fix_available": bool(code_fix or message),
        "fix_summary": summary,
        "installed_version": "",
        "fixed_version": "",
        "fix_references": _urls(metadata.get("references"), metadata.get("source")),
    }


def finding_fix(metadata: Any, raw: Any) -> dict[str, Any]:
    """The fix fields for one finding (see the module docstring)."""
    raw = raw if isinstance(raw, dict) else {}
    for build in (
        _package_fix,
        _secret_fix,
        _license_fix,
        _misconfiguration_fix,
        _semgrep_fix,
    ):
        fix = build(raw)
        if fix is not None:
            return fix
    text, url = _recommendation(metadata)
    return {
        "fix_available": bool(text),
        "fix_summary": text,
        "installed_version": "",
        "fixed_version": "",
        "fix_references": _urls(url, raw.get("PrimaryURL")),
    }


def empty_fix() -> dict[str, Any]:
    return {
        "fix_available": False,
        "fix_summary": "",
        "installed_version": "",
        "fixed_version": "",
        "fix_references": [],
    }
