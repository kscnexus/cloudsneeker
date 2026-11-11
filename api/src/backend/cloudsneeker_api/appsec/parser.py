"""Scan report parser: engine JSON to normalized findings and components.

Handles the standard report (``Results``) and the cluster report
(``Resources[].Results``) of schema version 2. Fields the parser does not
map to a column are kept under ``details["extra"]``, so nothing the scanner
reported is dropped. A missing or unexpected field never raises; it is
recorded in ``ParsedReport.warnings``.

Fingerprints identify a finding across scans of the same target. They leave
out what changes without the finding changing: line numbers where a resource
name or the matched text exists, the image tag in an OS package result, and
the installed version (an upgrade to a version that is still vulnerable is
the same finding).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

CATEGORY_VULNERABILITY = "vulnerability"
CATEGORY_MISCONFIGURATION = "misconfiguration"
CATEGORY_SECRET = "secret"
CATEGORY_LICENSE = "license"
CATEGORY_CODE = "code"

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "unknown",
    "INFO": "informational",
    "INFORMATIONAL": "informational",
}
SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "unknown": 0,
}

SUPPORTED_SCHEMA_VERSIONS = (2,)
UID_MAX = 300
TEXT_MAX = 5000
LICENSE_TEXT_MAX = 2000
CODE_LINES_MAX = 40
REDACTED = "[redacted]"

_VULN_KEYS = {
    "VulnerabilityID",
    "VendorIDs",
    "PkgID",
    "PkgName",
    "PkgPath",
    "PkgIdentifier",
    "InstalledVersion",
    "FixedVersion",
    "Status",
    "Layer",
    "SeveritySource",
    "PrimaryURL",
    "DataSource",
    "Title",
    "Description",
    "Severity",
    "CweIDs",
    "VendorSeverity",
    "CVSS",
    "References",
    "PublishedDate",
    "LastModifiedDate",
    "Fingerprint",
}
_MISCONFIG_KEYS = {
    "Type",
    "ID",
    "AVDID",
    "Title",
    "Description",
    "Message",
    "Namespace",
    "Query",
    "Resolution",
    "Severity",
    "PrimaryURL",
    "References",
    "Status",
    "Layer",
    "CauseMetadata",
}
_SECRET_KEYS = {
    "RuleID",
    "Category",
    "Severity",
    "Title",
    "StartLine",
    "EndLine",
    "Code",
    "Match",
    "Layer",
    "Offset",
}
_LICENSE_KEYS = {
    "Severity",
    "Category",
    "PkgName",
    "FilePath",
    "Name",
    "Text",
    "Confidence",
    "Link",
}
_MISCONFIG_ID_RE = re.compile(r"^([A-Z]+)-?(\d+)$")
_MASK_RE = re.compile(r"\*{3,}")


@dataclass
class NormalizedFinding:
    category: str
    title: str
    severity: str
    fingerprint: str = ""
    legacy_uid: str = ""
    finding_type: str = ""
    scanner: str = ""
    description: str = ""
    source_severity: str = ""
    rule_id: str = ""
    pkg_name: str = ""
    pkg_version: str = ""
    fixed_version: str = ""
    ecosystem: str = ""
    purl: str = ""
    location: str = ""
    file_path: str = ""
    start_line: int | None = None
    end_line: int | None = None
    resource: str = ""
    primary_url: str = ""
    cvss_score: float | None = None
    fix_available: bool | None = None
    direct_dependency: bool | None = None
    suppressed: bool = False
    suppression: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    # Scanner item as reported (secrets masked), for the shared Finding row.
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedComponent:
    name: str
    version: str = ""
    ref: str = ""
    ecosystem: str = ""
    package_class: str = ""
    purl: str = ""
    licenses: list[str] = field(default_factory=list)
    relationship: str = "unknown"
    dev: bool = False
    location: str = ""
    depends_on: list[str] = field(default_factory=list)


@dataclass
class ParsedReport:
    schema_version: int | None = None
    engine_version: str = ""
    artifact_name: str = ""
    artifact_type: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    findings: list[NormalizedFinding] = field(default_factory=list)
    components: list[NormalizedComponent] = field(default_factory=list)
    result_targets: list[str] = field(default_factory=list)
    passed_checks: int = 0
    failed_checks: int = 0
    resource_errors: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class ReportError(ValueError):
    """The document is not a scan report."""


def _text(value: Any, limit: int = TEXT_MAX) -> str:
    if value is None:
        return ""
    return str(value)[:limit]


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def normalize_severity(raw: Any) -> str:
    """Map a scanner severity to the product scale; unrecognized is unknown."""
    return SEVERITY_MAP.get(str(raw or "").strip().upper(), "unknown")


def normalize_check_id(raw: str) -> str:
    """Return one spelling for a check id.

    ``AVD-DS-0002``, ``DS-0002`` and ``DS002`` name the same check across
    check bundle versions; all become ``DS-0002``. Other ids are upper-cased.
    """
    value = str(raw or "").strip().upper()
    if value.startswith("AVD-"):
        value = value[4:]
    match = _MISCONFIG_ID_RE.match(value)
    if match:
        return f"{match.group(1)}-{int(match.group(2)):04d}"
    return value


def digest(*parts: Any) -> str:
    """SHA-256 over the parts, joined so that boundaries cannot shift."""
    joined = "\x1f".join(str(part if part is not None else "") for part in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def bounded_uid(value: str, limit: int = UID_MAX) -> str:
    """Cut ``value`` to ``limit`` characters, keeping it unique with a digest."""
    if len(value) <= limit:
        return value
    suffix = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{value[: limit - len(suffix) - 1]}-{suffix}"


def mask_text(value: Any) -> str:
    """Return text that is safe to store for a secret finding.

    The engine replaces the secret with asterisks. If a line carries no
    asterisk run it was not masked, so the whole line is withheld.
    """
    text = _text(value, 500)
    if not text:
        return ""
    return text if _MASK_RE.search(text) else REDACTED


def mask_secret(secret: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of a secret finding with no unmasked match or cause line."""
    masked = dict(secret)
    masked["Match"] = mask_text(secret.get("Match"))
    lines = []
    for line in _list(_dict(secret.get("Code")).get("Lines"))[:CODE_LINES_MAX]:
        if not isinstance(line, dict):
            continue
        clean = dict(line)
        if line.get("IsCause"):
            clean["Content"] = mask_text(line.get("Content"))
            if "Highlighted" in clean:
                clean["Highlighted"] = mask_text(line.get("Highlighted"))
        lines.append(clean)
    masked["Code"] = {"Lines": lines}
    return masked


def _code_lines(code: Any) -> list[dict[str, Any]]:
    lines = []
    for line in _list(_dict(code).get("Lines"))[:CODE_LINES_MAX]:
        if isinstance(line, dict):
            lines.append(
                {
                    "number": line.get("Number"),
                    "content": _text(line.get("Content"), 500),
                    "is_cause": bool(line.get("IsCause")),
                }
            )
    return lines


def _extra(item: dict[str, Any], known: set[str]) -> dict[str, Any]:
    return {key: value for key, value in item.items() if key not in known}


def _layer(item: dict[str, Any]) -> dict[str, Any]:
    layer = _dict(item.get("Layer"))
    return {
        key: layer[key] for key in ("Digest", "DiffID", "CreatedBy") if layer.get(key)
    }


def cvss_score(vuln: dict[str, Any]) -> float | None:
    """Base score from the vendor that set the severity, newest CVSS version.

    Falls back to NVD, then to the highest score any source reported.
    """
    cvss = _dict(vuln.get("CVSS"))
    if not cvss:
        return None

    def score(entry: Any) -> float | None:
        entry = _dict(entry)
        for key in ("V40Score", "V3Score", "V2Score"):
            value = entry.get(key)
            if (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and value > 0
            ):
                return float(value)
        return None

    for source in (str(vuln.get("SeveritySource") or ""), "nvd"):
        if source and score(cvss.get(source)) is not None:
            return score(cvss.get(source))
    scores = [
        value
        for value in (score(entry) for entry in cvss.values())
        if value is not None
    ]
    return max(scores) if scores else None


def _stable_location(result: dict[str, Any], scope: str) -> str:
    """Location used in fingerprints.

    An OS package result is named after the image and OS release
    (``app:1.2 (debian 12.5)``), which changes on every rebuild, so its class
    is used instead.
    """
    if str(result.get("Class") or "") == "os-pkgs":
        return f"{scope}|os-pkgs" if scope else "os-pkgs"
    target = _text(result.get("Target"), 600)
    return f"{scope}|{target}" if scope else target


def _vulnerability(
    vuln: dict[str, Any], result: dict[str, Any], *, mode: str, scope: str, target: str
) -> NormalizedFinding:
    vuln_id = _text(vuln.get("VulnerabilityID") or vuln.get("PkgID") or "unknown", 200)
    pkg = _text(vuln.get("PkgName") or vuln.get("PkgID") or "", 300)
    identifier = _dict(vuln.get("PkgIdentifier"))
    fixed = _text(vuln.get("FixedVersion"), 500)
    status = _text(vuln.get("Status"), 64)
    pkg_path = _text(vuln.get("PkgPath"), 600)
    severity = normalize_severity(vuln.get("Severity"))
    finding = NormalizedFinding(
        category=CATEGORY_VULNERABILITY,
        finding_type=_text(result.get("Class"), 64),
        scanner="vuln",
        title=_text(vuln.get("Title") or f"{vuln_id} in {pkg}", 500),
        description=_text(vuln.get("Description")),
        severity=severity,
        source_severity=_text(vuln.get("Severity"), 32),
        rule_id=vuln_id,
        pkg_name=pkg,
        pkg_version=_text(vuln.get("InstalledVersion"), 200),
        fixed_version=fixed,
        ecosystem=_text(result.get("Type"), 64),
        purl=_text(identifier.get("PURL"), 600),
        location=target,
        file_path=pkg_path,
        primary_url=_text(vuln.get("PrimaryURL"), 600),
        cvss_score=cvss_score(vuln),
        fix_available=bool(fixed),
        raw=vuln,
    )
    finding.details = {
        "status": status,
        "vendor_ids": _list(vuln.get("VendorIDs")),
        "severity_source": _text(vuln.get("SeveritySource"), 64),
        "vendor_severity": _dict(vuln.get("VendorSeverity")),
        "cvss": _dict(vuln.get("CVSS")),
        "cwe_ids": _list(vuln.get("CweIDs")),
        "references": [_text(item, 600) for item in _list(vuln.get("References"))[:50]],
        "data_source": _dict(vuln.get("DataSource")),
        "published_date": vuln.get("PublishedDate"),
        "last_modified_date": vuln.get("LastModifiedDate"),
        "pkg_id": _text(vuln.get("PkgID"), 600),
        "pkg_uid": _text(identifier.get("UID"), 200),
        "layer": _layer(vuln),
        "extra": _extra(vuln, _VULN_KEYS),
    }
    finding.fingerprint = digest(
        "vuln", vuln_id, pkg, pkg_path, _stable_location(result, scope)
    )
    finding.legacy_uid = bounded_uid(f"trivy-{mode}-{vuln_id}-{pkg or target}-{target}")
    return finding


def _misconfiguration(
    item: dict[str, Any], result: dict[str, Any], *, mode: str, scope: str, target: str
) -> NormalizedFinding:
    check_id = _text(item.get("ID") or item.get("AVDID") or "unknown", 200)
    cause = _dict(item.get("CauseMetadata"))
    lines = _code_lines(cause.get("Code"))
    resource = _text(cause.get("Resource"), 400)
    start = _int(cause.get("StartLine"))
    cause_text = "\n".join(
        str(line["content"]).strip() for line in lines if line["is_cause"]
    )
    if resource:
        anchor = resource
    elif cause_text:
        anchor = digest(cause_text)[:16]
    else:
        anchor = str(start or "")
    status = _text(item.get("Status") or "FAIL", 32).upper()
    finding = NormalizedFinding(
        category=CATEGORY_MISCONFIGURATION,
        finding_type=_text(item.get("Type") or result.get("Type"), 64),
        scanner="misconfig",
        title=_text(item.get("Title") or check_id, 500),
        description=_text(item.get("Description")),
        severity=normalize_severity(item.get("Severity")),
        source_severity=_text(item.get("Severity"), 32),
        rule_id=check_id,
        location=target,
        file_path=_text(result.get("Target"), 600),
        start_line=start,
        end_line=_int(cause.get("EndLine")),
        resource=resource,
        primary_url=_text(item.get("PrimaryURL"), 600),
        raw=item,
    )
    finding.details = {
        "message": _text(item.get("Message")),
        "resolution": _text(item.get("Resolution")),
        "namespace": _text(item.get("Namespace"), 300),
        "query": _text(item.get("Query"), 300),
        "legacy_id": _text(item.get("AVDID"), 100),
        "check_id": normalize_check_id(check_id),
        "status": status,
        "provider": _text(cause.get("Provider"), 100),
        "service": _text(cause.get("Service"), 100),
        "references": [_text(ref, 600) for ref in _list(item.get("References"))[:50]],
        "code": lines,
        "occurrences": _list(cause.get("Occurrences"))[:20],
        "rendered_cause": _text(_dict(cause.get("RenderedCause")).get("Raw"), 2000),
        "layer": _layer(item),
        "extra": _extra(item, _MISCONFIG_KEYS),
    }
    if status == "EXCEPTION":
        finding.suppressed = True
        finding.suppression = {"status": "exception", "source": "check exception"}
    finding.fingerprint = digest(
        "misconfig",
        normalize_check_id(check_id),
        f"{scope}|{_text(result.get('Target'), 600)}"
        if scope
        else _text(result.get("Target"), 600),
        anchor,
    )
    finding.legacy_uid = bounded_uid(f"trivy-{mode}-{check_id}-{target}")
    return finding


def _secret(
    item: dict[str, Any], result: dict[str, Any], *, mode: str, scope: str, target: str
) -> NormalizedFinding:
    masked = mask_secret(item)
    rule_id = _text(item.get("RuleID") or item.get("ID") or "unknown", 200)
    file_path = _text(result.get("Target"), 600)
    finding = NormalizedFinding(
        category=CATEGORY_SECRET,
        finding_type=_text(item.get("Category"), 64),
        scanner="secret",
        title=_text(item.get("Title") or rule_id, 500),
        description=f"{_text(item.get('Category'), 100) or 'Secret'} found in {file_path}.",
        severity=normalize_severity(item.get("Severity")),
        source_severity=_text(item.get("Severity"), 32),
        rule_id=rule_id,
        location=target,
        file_path=file_path,
        start_line=_int(item.get("StartLine")),
        end_line=_int(item.get("EndLine")),
        raw=masked,
    )
    finding.details = {
        "category": _text(item.get("Category"), 100),
        "match": masked["Match"],
        "code": _code_lines(masked.get("Code")),
        "layer": _layer(item),
        "extra": _extra(item, _SECRET_KEYS),
    }
    # The ordinal among identical matches is added by ``_number_duplicates``.
    finding.fingerprint = digest(
        "secret",
        rule_id,
        f"{scope}|{file_path}" if scope else file_path,
        masked["Match"],
    )
    finding.legacy_uid = bounded_uid(f"trivy-{mode}-secret-{rule_id}-{target}")
    return finding


def _license(
    item: dict[str, Any], result: dict[str, Any], *, mode: str, scope: str, target: str
) -> NormalizedFinding:
    name = _text(item.get("Name") or "unknown", 200)
    pkg = _text(item.get("PkgName"), 300)
    file_path = _text(item.get("FilePath"), 600)
    category = _text(item.get("Category") or "unknown", 64).lower()
    subject = pkg or file_path or target
    confidence = item.get("Confidence")
    finding = NormalizedFinding(
        category=CATEGORY_LICENSE,
        finding_type=category,
        scanner="license",
        title=f"{subject} uses the {name} license ({category})"[:500],
        severity=normalize_severity(item.get("Severity")),
        source_severity=_text(item.get("Severity"), 32),
        rule_id=name,
        pkg_name=pkg,
        ecosystem=_text(result.get("Type"), 64),
        location=target,
        file_path=file_path,
        primary_url=_text(item.get("Link"), 600),
        raw={key: value for key, value in item.items() if key != "Text"},
    )
    finding.details = {
        "license_category": category,
        "result_class": _text(result.get("Class"), 64),
        "confidence": confidence if isinstance(confidence, (int, float)) else None,
        "text": _text(item.get("Text"), LICENSE_TEXT_MAX),
        "extra": _extra(item, _LICENSE_KEYS),
    }
    finding.fingerprint = digest(
        "license", name, subject, _stable_location(result, scope)
    )
    finding.legacy_uid = bounded_uid(
        f"trivy-{mode}-license-{name}-{pkg or file_path or target}-{target}"
    )
    return finding


_BUILDERS = {
    "Vulnerabilities": _vulnerability,
    "Misconfigurations": _misconfiguration,
    "Secrets": _secret,
    "Licenses": _license,
}
_MODIFIED_TYPE_KEY = {
    "vulnerability": "Vulnerabilities",
    "misconfiguration": "Misconfigurations",
    "secret": "Secrets",
    "license": "Licenses",
}


def _component(
    pkg: dict[str, Any], result: dict[str, Any], target: str
) -> NormalizedComponent | None:
    name = _text(pkg.get("Name"), 300)
    if not name:
        return None
    identifier = _dict(pkg.get("Identifier"))
    relationship = _text(pkg.get("Relationship") or "unknown", 16).lower()
    if relationship == "unknown" and "Indirect" in pkg:
        # Older reports carry the deprecated boolean instead.
        relationship = "indirect" if pkg.get("Indirect") else "direct"
    version = _text(pkg.get("Version"), 200)
    return NormalizedComponent(
        name=name,
        version=version,
        ref=_text(pkg.get("ID") or f"{name}@{version}", 600),
        ecosystem=_text(result.get("Type"), 64),
        package_class=_text(result.get("Class"), 32),
        purl=_text(identifier.get("PURL"), 600),
        licenses=[_text(item, 200) for item in _list(pkg.get("Licenses"))[:20]],
        relationship=relationship,
        dev=bool(pkg.get("Dev")),
        location=target,
        depends_on=[_text(item, 600) for item in _list(pkg.get("DependsOn"))[:500]],
    )


def _parse_results(
    results: Any,
    parsed: ParsedReport,
    *,
    mode: str,
    scope: str,
    target_prefix: str = "",
) -> None:
    for result in _list(results):
        if not isinstance(result, dict):
            parsed.warnings.append("A result entry was not an object and was skipped.")
            continue
        raw_target = _text(result.get("Target") or "scan-target", 600)
        target = f"{target_prefix}{raw_target}"[:600]
        if target not in parsed.result_targets:
            parsed.result_targets.append(target)
        summary = _dict(result.get("MisconfSummary"))
        parsed.passed_checks += int(summary.get("Successes") or 0)
        parsed.failed_checks += int(summary.get("Failures") or 0)

        relationships = {}
        for pkg in _list(result.get("Packages")):
            if not isinstance(pkg, dict):
                continue
            component = _component(pkg, result, target)
            if component is not None:
                parsed.components.append(component)
                relationships[component.ref] = component.relationship

        for key, builder in _BUILDERS.items():
            for item in _list(result.get(key)):
                if not isinstance(item, dict):
                    parsed.warnings.append(f"A {key} entry was not an object.")
                    continue
                if (
                    key == "Misconfigurations"
                    and str(item.get("Status") or "").upper() == "PASS"
                ):
                    continue
                finding = builder(item, result, mode=mode, scope=scope, target=target)
                if key == "Vulnerabilities":
                    relationship = relationships.get(
                        finding.details.get("pkg_id") or ""
                    )
                    if relationship in ("direct", "root", "workspace"):
                        finding.direct_dependency = True
                    elif relationship == "indirect":
                        finding.direct_dependency = False
                    finding.details["relationship"] = relationship or "unknown"
                parsed.findings.append(finding)

        for modified in _list(result.get("ExperimentalModifiedFindings")):
            modified = _dict(modified)
            key = _MODIFIED_TYPE_KEY.get(str(modified.get("Type") or "").lower())
            item = modified.get("Finding")
            if key is None or not isinstance(item, dict):
                parsed.warnings.append("A suppressed finding had an unknown type.")
                continue
            finding = _BUILDERS[key](
                item, result, mode=mode, scope=scope, target=target
            )
            finding.suppressed = True
            finding.suppression = {
                "status": _text(modified.get("Status"), 64),
                "statement": _text(modified.get("Statement"), 1000),
                "source": _text(modified.get("Source"), 300),
            }
            parsed.findings.append(finding)


def _number_duplicates(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """Merge or number findings that share a fingerprint.

    Secrets with the same rule, file and masked text are distinct leaks, so
    each gets an ordinal (by line). Other duplicates are the same finding
    reported twice (the same package at two versions in one lock file); they
    merge into one, with every instance listed in ``details["instances"]``.
    """
    merged: dict[str, NormalizedFinding] = {}
    secret_seen: dict[str, int] = {}
    ordered = sorted(
        findings,
        key=lambda item: (item.fingerprint, item.start_line or 0, item.pkg_version),
    )
    for finding in ordered:
        if finding.category == CATEGORY_SECRET:
            ordinal = secret_seen.get(finding.fingerprint, 0)
            secret_seen[finding.fingerprint] = ordinal + 1
            if ordinal:
                finding.fingerprint = digest(finding.fingerprint, ordinal)
            merged[finding.fingerprint] = finding
            continue
        existing = merged.get(finding.fingerprint)
        if existing is None:
            merged[finding.fingerprint] = finding
            continue
        # A reported instance outranks a suppressed one.
        keep, other = (
            (finding, existing)
            if existing.suppressed and not finding.suppressed
            else (existing, finding)
        )
        instances = keep.details.setdefault(
            "instances",
            [{"version": keep.pkg_version, "start_line": keep.start_line}],
        )
        instances.append({"version": other.pkg_version, "start_line": other.start_line})
        merged[finding.fingerprint] = keep
    return list(merged.values())


def parse_report(report: Any, *, mode: str, scope: str = "") -> ParsedReport:
    """Parse one engine JSON report.

    Args:
        report: Parsed JSON document.
        mode: Target type (``repo``, ``image``, ``k8s``, ...).
        scope: Stable name of the artifact inside the target, for targets
            that scan several (one image of an image list). Empty otherwise.

    Returns:
        Findings (deduplicated by fingerprint), components and metadata.

    Raises:
        ReportError: The document is not an object.
    """
    if not isinstance(report, dict):
        raise ReportError("The scan report root must be an object.")
    parsed = ParsedReport()
    schema = report.get("SchemaVersion")
    parsed.schema_version = schema if isinstance(schema, int) else None
    if parsed.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        parsed.warnings.append(
            f"Report schema version {schema!r} is not one this parser was "
            "written for; fields it does not know are kept as extra data."
        )
    parsed.engine_version = _text(_dict(report.get("Trivy")).get("Version"), 64)
    parsed.artifact_name = _text(
        report.get("ArtifactName") or report.get("ClusterName"), 600
    )
    parsed.artifact_type = _text(report.get("ArtifactType"), 64)

    metadata = _dict(report.get("Metadata"))
    keep = {}
    for key in (
        "RepoURL",
        "Branch",
        "Tags",
        "Commit",
        "CommitMsg",
        "Author",
        "Committer",
        "ImageID",
        "RepoTags",
        "RepoDigests",
        "Size",
        "OS",
    ):
        if metadata.get(key):
            keep[key] = metadata[key]
    for key in ("ReportID", "ArtifactID", "CreatedAt"):
        if report.get(key):
            keep[key] = report[key]
    parsed.metadata = keep

    if "Resources" in report or "Findings" in report or "ClusterName" in report:
        parsed.artifact_type = parsed.artifact_type or "kubernetes"
        resources = report.get("Resources")
        if resources is None:
            resources = report.get("Findings")
        for resource in _list(resources):
            resource = _dict(resource)
            name = "/".join(
                part
                for part in (
                    _text(resource.get("Namespace"), 100),
                    _text(resource.get("Kind"), 100),
                    _text(resource.get("Name"), 200),
                )
                if part
            )
            if resource.get("Error"):
                parsed.resource_errors.append(
                    {"resource": name, "error": _text(resource.get("Error"), 500)}
                )
            before = len(parsed.findings)
            _parse_results(
                resource.get("Results"),
                parsed,
                mode=mode,
                scope=scope,
                target_prefix=f"{name}/" if name else "",
            )
            for finding in parsed.findings[before:]:
                finding.resource = finding.resource or name
                finding.details["kubernetes"] = {
                    "namespace": _text(resource.get("Namespace"), 100),
                    "kind": _text(resource.get("Kind"), 100),
                    "name": _text(resource.get("Name"), 200),
                }
    else:
        _parse_results(report.get("Results"), parsed, mode=mode, scope=scope)

    parsed.findings = _number_duplicates(parsed.findings)
    return parsed


# --- Static analysis (OpenGrep) -----------------------------------------------


def parse_code_rows(rows: list[dict[str, Any]]) -> list[NormalizedFinding]:
    """Normalize the static analysis rows ``trivy_import`` already builds.

    Args:
        rows: Output of ``opengrep_results_to_finding_rows``.

    Returns:
        One code finding per row; the row UID is kept as the triage UID.
    """
    findings = []
    for row in rows:
        metadata = _dict(row.get("check_metadata"))
        raw = _dict(row.get("raw_result"))
        start = _int(_dict(raw.get("start")).get("line"))
        end = _int(_dict(raw.get("end")).get("line"))
        path = _text(raw.get("path") or row.get("resource_uid"), 600)
        remediation = _dict(_dict(metadata.get("Remediation")).get("Recommendation"))
        finding = NormalizedFinding(
            category=CATEGORY_CODE,
            finding_type="sast",
            scanner="sast",
            title=_text(metadata.get("CheckTitle") or row.get("check_id"), 500),
            description=_text(metadata.get("Description")),
            severity=str(row.get("severity") or "unknown"),
            source_severity=_text(_dict(raw.get("extra")).get("severity"), 32),
            rule_id=_text(row.get("check_id"), 200),
            location=path,
            file_path=path,
            start_line=start,
            end_line=end,
            primary_url=_text(metadata.get("RelatedUrl"), 600),
            raw=raw,
        )
        finding.details = {
            "categories": _list(metadata.get("Categories")),
            "references": _list(metadata.get("AdditionalURLs")),
            "resolution": _text(remediation.get("Text")),
            "fix": _text(
                _dict(_dict(metadata.get("Remediation")).get("Code")).get("Other"), 2000
            ),
            "risk": _text(metadata.get("Risk"), 2000),
        }
        finding.fingerprint = digest("code", finding.rule_id, path, start, end)
        finding.legacy_uid = str(row.get("uid") or "")
        findings.append(finding)
    return _number_duplicates(findings)


def finding_stats(findings: list[NormalizedFinding]) -> dict[str, Any]:
    """Counts by category and severity, reported and suppressed apart."""
    stats: dict[str, Any] = {"total": 0, "suppressed": 0, "by_category": {}}
    for finding in findings:
        if finding.suppressed:
            stats["suppressed"] += 1
            continue
        stats["total"] += 1
        bucket = stats["by_category"].setdefault(finding.category, {"total": 0})
        bucket["total"] += 1
        bucket[finding.severity] = bucket.get(finding.severity, 0) + 1
    return stats
