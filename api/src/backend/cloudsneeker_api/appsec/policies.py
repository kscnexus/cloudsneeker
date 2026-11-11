"""Tenant policy documents: validation and the files a scan receives.

Kinds: custom Rego checks, secret detection rules, license policy, ignore
rules and VEX documents. Validation checks structure only; the engine
remains the judge of Rego and regular expression syntax, and a scan that
rejects a policy fails with the engine's message.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml
from cloudsneeker_api.appsec import capabilities as caps

KIND_REGO = "rego_check"
KIND_SECRET = "secret_rules"
KIND_LICENSE = "license_policy"
KIND_IGNORE = "ignore_rules"
KIND_VEX = "vex"
KINDS = (KIND_REGO, KIND_SECRET, KIND_LICENSE, KIND_IGNORE, KIND_VEX)

MAX_CONTENT_CHARS = 200_000

SECRET_TOP_KEYS = {
    "rules",
    "allow-rules",
    "enable-builtin-rules",
    "disable-rules",
    "disable-allow-rules",
    "skip-patterns",
}
SECRET_RULE_REQUIRED = ("id", "category", "title", "severity", "regex")
IGNORE_SECTIONS = ("vulnerabilities", "misconfigurations", "secrets", "licenses")
IGNORE_ENTRY_KEYS = {"id", "paths", "purls", "expired_at", "statement"}
LICENSE_KEYS = {*caps.LICENSE_CATEGORIES, "ignored"} - {"unknown"}

_PACKAGE_RE = re.compile(r"^\s*package\s+([A-Za-z_][\w.]*)\s*$", re.MULTILINE)
_DENY_RE = re.compile(r"^\s*(deny|warn)\b", re.MULTILINE)

VEX_OPENVEX = "openvex"
VEX_CSAF = "csaf"
VEX_CYCLONEDX = "cyclonedx"


@dataclass
class Validation:
    valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    info: dict[str, Any] = field(default_factory=dict)

    def error(self, message: str) -> None:
        self.valid = False
        self.errors.append(message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "info": self.info,
        }


def _load_mapping(content: str, result: Validation) -> dict[str, Any] | None:
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        result.error(f"Not valid YAML: {str(exc).splitlines()[0]}")
        return None
    if not isinstance(data, dict):
        result.error("The document must be a mapping of keys to values.")
        return None
    return data


def _string_list(value: Any, name: str, result: Validation) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        result.error(f"{name} must be a list of text values.")
        return []
    return [item.strip() for item in value]


def rego_namespace(content: str) -> str:
    """Return the Rego package of a check, or an empty string."""
    match = _PACKAGE_RE.search(content or "")
    return match.group(1) if match else ""


def _validate_rego(content: str, result: Validation) -> None:
    namespace = rego_namespace(content)
    if not namespace:
        result.error("The check needs a `package` declaration.")
        return
    if namespace == "builtin" or namespace.startswith("builtin."):
        result.error("The `builtin` package namespace is reserved for built-in checks.")
    if not _DENY_RE.search(content):
        result.error("The check needs at least one `deny` rule.")
    if "# METADATA" not in content:
        result.warnings.append(
            "No `# METADATA` block: the finding will have no title, severity "
            "or id of its own."
        )
    elif not re.search(r"^#\s+id:\s*\S+", content, re.MULTILINE):
        result.warnings.append(
            "The metadata has no `custom.id`; add one to identify the check."
        )
    result.info["namespace"] = namespace


def _validate_secret(content: str, result: Validation) -> None:
    data = _load_mapping(content, result)
    if data is None:
        return
    unknown = sorted(set(data) - SECRET_TOP_KEYS)
    if unknown:
        result.error(f"Unknown keys: {', '.join(unknown)}.")
    rules = data.get("rules") or []
    if not isinstance(rules, list):
        result.error("rules must be a list.")
        rules = []
    ids = []
    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            result.error(f"rules[{index}] must be a mapping.")
            continue
        missing = [key for key in SECRET_RULE_REQUIRED if not rule.get(key)]
        if missing:
            result.error(f"rules[{index}] is missing: {', '.join(missing)}.")
        severity = str(rule.get("severity") or "").upper()
        if severity and severity not in caps.SEVERITIES:
            result.error(
                f"rules[{index}].severity must be one of {', '.join(caps.SEVERITIES)}."
            )
        if rule.get("id"):
            ids.append(str(rule["id"]))
    duplicates = sorted({item for item in ids if ids.count(item) > 1})
    if duplicates:
        result.error(f"Duplicate rule ids: {', '.join(duplicates)}.")
    for key in (
        "enable-builtin-rules",
        "disable-rules",
        "disable-allow-rules",
        "skip-patterns",
    ):
        _string_list(data.get(key), key, result)
    if data.get("enable-builtin-rules") and data.get("disable-rules"):
        result.warnings.append(
            "Both enable-builtin-rules and disable-rules are set; "
            "disable-rules takes precedence."
        )
    if "skip-patterns" in data:
        result.warnings.append(
            "skip-patterns replaces the default skip list; list the defaults "
            "you still want."
        )
    result.info["custom_rules"] = len(ids)


def _validate_license(content: str, result: Validation) -> None:
    data = _load_mapping(content, result)
    if data is None:
        return
    unknown = sorted(set(data) - LICENSE_KEYS)
    if unknown:
        result.error(
            f"Unknown keys: {', '.join(unknown)}. Use: {', '.join(sorted(LICENSE_KEYS))}."
        )
    seen: dict[str, str] = {}
    for key in sorted(LICENSE_KEYS - {"ignored"}):
        for name in _string_list(data.get(key), key, result):
            if name in seen:
                result.error(f"{name} is listed under both {seen[name]} and {key}.")
            seen[name] = key
    _string_list(data.get("ignored"), "ignored", result)
    result.info["classified"] = len(seen)


def _validate_ignore(content: str, result: Validation) -> None:
    data = _load_mapping(content, result)
    if data is None:
        return
    unknown = sorted(set(data) - set(IGNORE_SECTIONS))
    if unknown:
        result.error(
            f"Unknown sections: {', '.join(unknown)}. Use: {', '.join(IGNORE_SECTIONS)}."
        )
    total = 0
    for section in IGNORE_SECTIONS:
        entries = data.get(section) or []
        if not isinstance(entries, list):
            result.error(f"{section} must be a list.")
            continue
        for index, entry in enumerate(entries, start=1):
            where = f"{section}[{index}]"
            if not isinstance(entry, dict) or not entry.get("id"):
                result.error(f"{where} needs an `id`.")
                continue
            extra = sorted(set(entry) - IGNORE_ENTRY_KEYS)
            if extra:
                result.error(f"{where} has unknown keys: {', '.join(extra)}.")
            _string_list(entry.get("paths"), f"{where}.paths", result)
            if entry.get("purls") and section != "vulnerabilities":
                result.error(f"{where}.purls applies to vulnerabilities only.")
            _string_list(entry.get("purls"), f"{where}.purls", result)
            expires = entry.get("expired_at")
            if expires is not None and not isinstance(expires, date):
                try:
                    date.fromisoformat(str(expires))
                except ValueError:
                    result.error(f"{where}.expired_at must be a date (yyyy-mm-dd).")
            if not entry.get("statement"):
                result.warnings.append(
                    f"{where} has no statement explaining the exception."
                )
            total += 1
    result.info["entries"] = total


def vex_format(document: Any) -> str:
    """Return the VEX format of a parsed document, or an empty string."""
    if not isinstance(document, dict):
        return ""
    if "openvex" in str(document.get("@context") or "").lower():
        return VEX_OPENVEX
    category = (
        str((document.get("document") or {}).get("category") or "").lower()
        if isinstance(document.get("document"), dict)
        else ""
    )
    if category == "csaf_vex":
        return VEX_CSAF
    if str(document.get("bomFormat") or "").lower() == "cyclonedx":
        return VEX_CYCLONEDX
    return ""


def _validate_vex(content: str, result: Validation) -> None:
    try:
        document = json.loads(content)
    except json.JSONDecodeError as exc:
        result.error(f"Not valid JSON: {exc.msg} (line {exc.lineno}).")
        return
    kind = vex_format(document)
    if not kind:
        result.error("Not an OpenVEX, CSAF VEX or CycloneDX VEX document.")
        return
    result.info["format"] = kind
    if kind == VEX_CYCLONEDX:
        result.warnings.append(
            "A CycloneDX VEX document applies only to scans of a CycloneDX SBOM."
        )
    statements = (
        document.get("statements")
        if kind == VEX_OPENVEX
        else document.get("vulnerabilities")
    )
    if not isinstance(statements, list) or not statements:
        result.error("The document has no statements.")
    else:
        result.info["statements"] = len(statements)


_VALIDATORS = {
    KIND_REGO: _validate_rego,
    KIND_SECRET: _validate_secret,
    KIND_LICENSE: _validate_license,
    KIND_IGNORE: _validate_ignore,
    KIND_VEX: _validate_vex,
}


def validate_policy(kind: str, content: Any) -> Validation:
    """Validate the content of a policy.

    Args:
        kind: One of :data:`KINDS`.
        content: Document text.

    Returns:
        Errors (the policy cannot be used), warnings and extracted facts.
    """
    result = Validation()
    if kind not in _VALIDATORS:
        result.error(f"Unknown policy kind: {kind}.")
        return result
    if not isinstance(content, str) or not content.strip():
        result.error("The policy has no content.")
        return result
    if len(content) > MAX_CONTENT_CHARS:
        result.error(f"The policy is larger than {MAX_CONTENT_CHARS} characters.")
        return result
    _VALIDATORS[kind](content, result)
    return result


@dataclass
class PolicyFiles:
    """Flags and facts produced by :func:`write_policy_files`."""

    flags: list[str] = field(default_factory=list)
    has_vex: bool = False
    applied: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)


def write_policy_files(
    policies: list[dict[str, Any]],
    work_dir: Path,
    *,
    target_type: str,
    scanners: list[str],
    sbom_format: str = "",
) -> PolicyFiles:
    """Write the enabled policies of a tenant for one scan.

    A policy is applied only when the scan runs the scanner it concerns and
    the command accepts its flag; otherwise it is listed under ``skipped``
    with the reason, which the run records.

    Args:
        policies: Dicts with ``id``, ``kind``, ``name``, ``version`` and
            ``content``; invalid ones must already be filtered out.
        work_dir: Scan directory; files go under ``policies/``.
        target_type: Key of ``capabilities.TARGETS``.
        scanners: Scanners of the scan.
        sbom_format: Format of the scanned SBOM for an SBOM target.

    Returns:
        Extra engine flags and what was applied or skipped.
    """
    out = PolicyFiles()
    root = work_dir / "policies"
    root.mkdir(parents=True, exist_ok=True)
    option_names = set(caps.options_for(target_type))

    def note(policy: dict[str, Any], reason: str = "") -> None:
        entry = {
            "id": str(policy.get("id") or ""),
            "kind": policy["kind"],
            "name": policy.get("name") or "",
            "version": policy.get("version"),
        }
        if reason:
            out.skipped.append({**entry, "reason": reason})
        else:
            out.applied.append(entry)

    by_kind: dict[str, list[dict[str, Any]]] = {kind: [] for kind in KINDS}
    for policy in policies:
        if policy.get("kind") in by_kind:
            by_kind[policy["kind"]].append(policy)

    # Custom checks.
    if by_kind[KIND_REGO]:
        if caps.SCANNER_MISCONFIG not in scanners:
            for policy in by_kind[KIND_REGO]:
                note(policy, "The misconfiguration scanner is not part of this scan.")
        else:
            checks_dir = root / "checks"
            checks_dir.mkdir(exist_ok=True)
            namespaces: list[str] = []
            for index, policy in enumerate(by_kind[KIND_REGO]):
                namespace = rego_namespace(policy["content"])
                (checks_dir / f"check_{index}.rego").write_text(
                    policy["content"], encoding="utf-8"
                )
                if namespace and namespace not in namespaces:
                    namespaces.append(namespace)
                note(policy)
            out.flags.extend(["--config-check", str(checks_dir)])
            if namespaces:
                out.flags.extend(["--check-namespaces", ",".join(namespaces)])

    # Secret rules: one merged configuration.
    if by_kind[KIND_SECRET]:
        if caps.SCANNER_SECRET not in scanners or target_type == "sbom":
            for policy in by_kind[KIND_SECRET]:
                note(policy, "The secret scanner is not part of this scan.")
        else:
            merged: dict[str, list[Any]] = {}
            for policy in by_kind[KIND_SECRET]:
                data = yaml.safe_load(policy["content"]) or {}
                for key in SECRET_TOP_KEYS:
                    if key in data and isinstance(data[key], list):
                        merged.setdefault(key, []).extend(data[key])
                note(policy)
            path = root / "secret.yaml"
            path.write_text(yaml.safe_dump(merged, sort_keys=False), encoding="utf-8")
            out.flags.extend(["--secret-config", str(path)])

    # Ignore rules: one merged ignore file.
    if by_kind[KIND_IGNORE]:
        merged_ignore: dict[str, list[Any]] = {}
        for policy in by_kind[KIND_IGNORE]:
            data = yaml.safe_load(policy["content"]) or {}
            for section in IGNORE_SECTIONS:
                if isinstance(data.get(section), list):
                    merged_ignore.setdefault(section, []).extend(data[section])
            note(policy)
        path = root / "ignore.yaml"
        path.write_text(
            yaml.safe_dump(merged_ignore, sort_keys=False, default_flow_style=False),
            encoding="utf-8",
        )
        out.flags.extend(["--ignorefile", str(path)])

    # License policy: classification through the engine configuration file.
    if by_kind[KIND_LICENSE]:
        if caps.SCANNER_LICENSE not in scanners:
            for policy in by_kind[KIND_LICENSE]:
                note(policy, "The license scanner is not part of this scan.")
        else:
            classification: dict[str, list[str]] = {}
            ignored: list[str] = []
            for policy in by_kind[KIND_LICENSE]:
                data = yaml.safe_load(policy["content"]) or {}
                for key in LICENSE_KEYS - {"ignored"}:
                    for name in data.get(key) or []:
                        # A later policy moves a license to its category.
                        for names in classification.values():
                            if name in names:
                                names.remove(name)
                        classification.setdefault(key, []).append(name)
                ignored.extend(
                    name for name in data.get("ignored") or [] if name not in ignored
                )
                note(policy)
            classification = {
                key: names for key, names in classification.items() if names
            }
            if classification:
                path = root / "engine.yaml"
                path.write_text(
                    yaml.safe_dump({"license": classification}, sort_keys=True),
                    encoding="utf-8",
                )
                out.flags.extend(["--config", str(path)])
            if ignored and "ignored_licenses" in option_names:
                out.flags.extend(["--ignored-licenses", ",".join(ignored)])

    # VEX documents.
    for index, policy in enumerate(by_kind[KIND_VEX]):
        if caps.SCANNER_VULN not in scanners:
            note(policy, "The vulnerability scanner is not part of this scan.")
            continue
        try:
            kind = vex_format(json.loads(policy["content"]))
        except json.JSONDecodeError:
            kind = ""
        if kind == VEX_CYCLONEDX and not (
            target_type == "sbom" and sbom_format == "cyclonedx"
        ):
            note(
                policy, "A CycloneDX VEX document applies only to CycloneDX SBOM scans."
            )
            continue
        path = root / f"vex_{index}.json"
        path.write_text(policy["content"], encoding="utf-8")
        out.flags.extend(["--vex", str(path)])
        out.has_vex = True
        note(policy)

    return out
