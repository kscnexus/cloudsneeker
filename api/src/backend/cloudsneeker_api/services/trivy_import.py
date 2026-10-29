"""Import Trivy and OpenGrep JSON reports into shared Scan / Finding rows."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any
from uuid import uuid4

from api.db_utils import rls_transaction
from api.models import Finding, Provider, Resource, ResourceFindingMapping, Scan, StateChoices
from django.utils import timezone
from uuid6 import uuid7

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "low",
    "INFO": "informational",
    "INFORMATIONAL": "informational",
}


SAST_MODE = "sast"

# OpenGrep ``extra.severity`` -> Finding severity. Rule packs may also use the
# newer CRITICAL / HIGH / MEDIUM / LOW levels.
OPENGREP_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INVENTORY": "informational",
    "EXPERIMENT": "informational",
}

# ``metadata.security-severity`` (GitLab rule packs) -> Finding severity.
SECURITY_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "informational",
    "INFORMATIONAL": "informational",
}

FINDING_UID_MAX = 300
CHECK_ID_MAX = 100
MAX_LINES_CHARS = 2000
# Rules loaded from a local directory get the directory path as a dotted id
# prefix (``opt.opengrep.rules.python.eval.<id>``); vendored ids look like
# ``<lang>_<category>_rule-<name>``.
_VENDORED_RULE_ID = re.compile(r"(?:^|\.)([a-z0-9]+_[a-z0-9_-]+?_rule-.+)$")


def _normalize_severity(raw: str | None) -> str:
    key = str(raw or "MEDIUM").upper()
    return SEVERITY_MAP.get(key, "medium")


def bounded_uid(value: str, limit: int = FINDING_UID_MAX) -> str:
    """Return ``value`` cut to ``limit`` characters without losing uniqueness.

    Long values keep a prefix plus a SHA-256 digest of the full value, so two
    findings that differ only past the limit get different UIDs.

    Args:
        value: Full UID.
        limit: Maximum length (``Finding.uid`` is 300).

    Returns:
        The bounded UID.
    """
    if len(value) <= limit:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{value[: limit - len(digest) - 1]}-{digest}"


def normalize_rule_id(check_id: str) -> str:
    """Strip the directory prefix OpenGrep adds to locally loaded rule ids.

    Args:
        check_id: ``check_id`` from an OpenGrep result.

    Returns:
        The rule id as written in the rule file, or ``check_id`` unchanged.
    """
    match = _VENDORED_RULE_ID.search(check_id)
    return match.group(1) if match else check_id


def _as_list(value: Any) -> list[str]:
    """Return ``value`` as a list of non-empty strings."""
    if value is None:
        return []
    if not isinstance(value, list):
        value = [value]
    return [str(item).strip() for item in value if str(item or "").strip()]


def _as_dict(value: Any) -> dict[str, Any]:
    """Return ``value`` when it is a dict, else an empty dict."""
    return value if isinstance(value, dict) else {}


def opengrep_severity(extra: dict[str, Any]) -> str:
    """Return the Finding severity for one OpenGrep result.

    ``metadata.security-severity`` wins when present. Otherwise the rule
    severity maps ERROR -> high, WARNING -> medium, INFO -> low. A ``high``
    result whose metadata says both ``impact`` and ``confidence`` are HIGH is
    raised to ``critical``.

    Args:
        extra: The result's ``extra`` object.

    Returns:
        One of critical, high, medium, low, informational.
    """
    metadata = _as_dict(extra.get("metadata"))
    declared = str(metadata.get("security-severity") or "").strip().upper()
    if declared in SECURITY_SEVERITY_MAP:
        severity = SECURITY_SEVERITY_MAP[declared]
    else:
        severity = OPENGREP_SEVERITY_MAP.get(
            str(extra.get("severity") or "WARNING").upper(), "medium"
        )
    impact = str(metadata.get("impact") or "").upper()
    confidence = str(metadata.get("confidence") or "").upper()
    if severity == "high" and impact == "HIGH" and confidence == "HIGH":
        return "critical"
    return severity


def _line(position: dict[str, Any], default: int = 0) -> int:
    """Return ``position['line']`` as an int, or ``default``."""
    try:
        return int(position.get("line") or default)
    except (TypeError, ValueError):
        return default


def opengrep_results_to_finding_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Map an OpenGrep ``--json`` report into Finding field dicts.

    Each result is one FAIL finding on the source file. Results suppressed
    in code (``nosemgrep``) are skipped.

    Args:
        report: Parsed OpenGrep JSON with paths relative to the source tree.

    Returns:
        List of finding field mappings ready for Finding.create.
    """
    results = report.get("results") or []
    if not isinstance(results, list):
        return []

    rows: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        extra = _as_dict(result.get("extra"))
        if extra.get("is_ignored"):
            continue
        metadata = _as_dict(extra.get("metadata"))
        rule_id = normalize_rule_id(str(result.get("check_id") or "opengrep-rule"))
        path = str(result.get("path") or "source")
        start_line = _line(_as_dict(result.get("start")))
        end_line = _line(_as_dict(result.get("end")), start_line)
        location = f"{path}:{start_line}-{end_line}"
        severity = opengrep_severity(extra)
        message = str(extra.get("message") or rule_id).strip()
        title = str(metadata.get("shortDescription") or rule_id).strip()
        cwe = _as_list(metadata.get("cwe"))
        owasp = _as_list(metadata.get("owasp"))
        references = _as_list(metadata.get("references"))
        reference = references[0] if references else ""
        fix = str(extra.get("fix") or "").strip()

        risk_parts = [title]
        if cwe:
            risk_parts.append(f"Weakness: {', '.join(cwe)}.")
        for label, key in (("Impact", "impact"), ("Likelihood", "likelihood")):
            if metadata.get(key):
                risk_parts.append(f"{label}: {metadata[key]}.")
        raw = dict(result)
        if isinstance(extra.get("lines"), str):
            raw["extra"] = {**extra, "lines": extra["lines"][:MAX_LINES_CHARS]}
        recommendation = (
            f"Apply this fix: {fix}"
            if fix
            else "Review the flagged code and apply the guidance in the description."
        )

        rows.append(
            {
                "uid": bounded_uid(f"opengrep-{SAST_MODE}-{rule_id}-{location}"),
                "status": "FAIL",
                "status_extended": f"{location}: {message}"[:5000],
                "severity": severity,
                "impact": severity,
                "check_id": rule_id[:CHECK_ID_MAX],
                "check_metadata": {
                    "CheckID": rule_id[:CHECK_ID_MAX],
                    "CheckTitle": title[:256],
                    "Description": message[:2000],
                    "Risk": " ".join(risk_parts)[:2000],
                    "Severity": severity,
                    "Provider": SAST_MODE,
                    "ServiceName": SAST_MODE,
                    "ResourceType": "source-file",
                    "Categories": [*cwe, *owasp][:20],
                    "RelatedUrl": reference,
                    "AdditionalURLs": references[:10],
                    "Remediation": {
                        "Code": {
                            "CLI": "",
                            "NativeIaC": "",
                            "Other": fix[:2000],
                            "Terraform": "",
                        },
                        "Recommendation": {
                            "Text": recommendation[:2000],
                            "Url": reference,
                        },
                    },
                },
                "raw_result": raw,
                "resource_regions": ["global"],
                "resource_services": [SAST_MODE],
                "resource_types": ["source-file"],
                "resource_uid": path[:FINDING_UID_MAX],
                "resource_name": path[:FINDING_UID_MAX],
            }
        )
    return rows


def report_to_finding_rows(report: dict[str, Any], *, mode: str) -> list[dict[str, Any]]:
    """Map a report from the engine that serves ``mode`` into Finding dicts.

    Args:
        report: Parsed Trivy or OpenGrep JSON.
        mode: Hub mode.

    Returns:
        List of finding field mappings.
    """
    if mode == SAST_MODE:
        return opengrep_results_to_finding_rows(report)
    return trivy_results_to_finding_rows(report, mode=mode)


def compact_report_output(report: dict[str, Any], *, mode: str) -> dict[str, Any]:
    """Return the small summary stored on ``TrivyRun.output``.

    Args:
        report: Parsed Trivy or OpenGrep JSON.
        mode: Hub mode.

    Returns:
        ``result_targets`` (up to 50), plus ``rulesets`` and ``error_count``
        for SAST.
    """
    if mode == SAST_MODE:
        paths: list[str] = []
        for item in report.get("results") or []:
            path = str(item.get("path") or "") if isinstance(item, dict) else ""
            if path and path not in paths:
                paths.append(path)
        errors = report.get("errors")
        return {
            "result_targets": paths[:50],
            "rulesets": list(report.get("cloudsneeker_rulesets") or []),
            "error_count": len(errors) if isinstance(errors, list) else 0,
        }
    return {
        "result_targets": [
            str(item.get("Target") or "")
            for item in (report.get("Results") or [])
            if isinstance(item, dict)
        ][:50],
    }


def trivy_results_to_finding_rows(
    report: dict[str, Any], *, mode: str
) -> list[dict[str, Any]]:
    """Map a Trivy JSON report into Finding field dicts.

    Args:
        report: Parsed Trivy ``-f json`` document.
        mode: Trivy Hub mode (iac, image, fs, repo, sbom, k8s).

    Returns:
        List of finding field mappings ready for Finding.create.
    """
    results = report.get("Results") or []
    if not isinstance(results, list):
        return []

    rows: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or result.get("target") or "trivy-target")
        resource_type = str(result.get("Type") or result.get("Class") or mode)
        service = str(result.get("Class") or mode)

        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = str(vuln.get("VulnerabilityID") or vuln.get("PkgID") or uuid4())
            pkg = str(vuln.get("PkgName") or vuln.get("PkgID") or target)
            title = str(vuln.get("Title") or vuln_id)
            severity = _normalize_severity(vuln.get("Severity"))
            uid = f"trivy-{mode}-{vuln_id}-{pkg}-{target}"[:300]
            rows.append(
                {
                    "uid": uid,
                    "status": "FAIL",
                    "status_extended": str(
                        vuln.get("Description") or vuln.get("PrimaryURL") or title
                    )[:5000],
                    "severity": severity,
                    "impact": severity,
                    "check_id": vuln_id[:100],
                    "check_metadata": {
                        "CheckTitle": title[:256],
                        "Description": str(vuln.get("Description") or "")[:2000],
                        "Severity": severity,
                        "Provider": "trivy",
                        "ServiceName": service[:100],
                        "ResourceType": resource_type[:100],
                    },
                    "raw_result": vuln,
                    "resource_regions": ["global"],
                    "resource_services": [service[:100]],
                    "resource_types": [resource_type[:100]],
                    "resource_uid": f"{target}:{pkg}"[:300],
                    "resource_name": pkg[:300] or target[:300],
                }
            )

        for misconfig in result.get("Misconfigurations") or []:
            if not isinstance(misconfig, dict):
                continue
            check_id = str(
                misconfig.get("ID") or misconfig.get("AVDID") or uuid4()
            )
            title = str(misconfig.get("Title") or check_id)
            severity = _normalize_severity(misconfig.get("Severity"))
            status_code = str(misconfig.get("Status") or "FAIL").upper()
            if status_code not in {"FAIL", "PASS", "MANUAL"}:
                status_code = "FAIL"
            uid = f"trivy-{mode}-{check_id}-{target}"[:300]
            rows.append(
                {
                    "uid": uid,
                    "status": status_code,
                    "status_extended": str(
                        misconfig.get("Description") or misconfig.get("Message") or title
                    )[:5000],
                    "severity": severity,
                    "impact": severity,
                    "check_id": check_id[:100],
                    "check_metadata": {
                        "CheckTitle": title[:256],
                        "Description": str(misconfig.get("Description") or "")[:2000],
                        "Severity": severity,
                        "Provider": "trivy",
                        "ServiceName": service[:100],
                        "ResourceType": resource_type[:100],
                    },
                    "raw_result": misconfig,
                    "resource_regions": ["global"],
                    "resource_services": [service[:100]],
                    "resource_types": [resource_type[:100]],
                    "resource_uid": target[:300],
                    "resource_name": target[:300],
                }
            )

        for secret in result.get("Secrets") or []:
            if not isinstance(secret, dict):
                continue
            check_id = str(secret.get("RuleID") or secret.get("ID") or uuid4())
            title = str(secret.get("Title") or check_id)
            severity = _normalize_severity(secret.get("Severity"))
            uid = f"trivy-{mode}-secret-{check_id}-{target}"[:300]
            rows.append(
                {
                    "uid": uid,
                    "status": "FAIL",
                    "status_extended": str(secret.get("Match") or title)[:5000],
                    "severity": severity,
                    "impact": severity,
                    "check_id": check_id[:100],
                    "check_metadata": {
                        "CheckTitle": title[:256],
                        "Description": str(secret.get("Category") or title)[:2000],
                        "Severity": severity,
                        "Provider": "trivy",
                        "ServiceName": "secret",
                        "ResourceType": resource_type[:100],
                    },
                    "raw_result": secret,
                    "resource_regions": ["global"],
                    "resource_services": ["secret"],
                    "resource_types": [resource_type[:100]],
                    "resource_uid": target[:300],
                    "resource_name": target[:300],
                }
            )

    return rows


def import_trivy_report(
    *,
    tenant_id: str,
    provider: Provider,
    report: dict[str, Any],
    mode: str,
    scan_name: str | None = None,
    started_at: datetime | None = None,
    rows: list[dict[str, Any]] | None = None,
) -> Scan:
    """Create a completed Scan and Finding rows from a Trivy or OpenGrep report.

    Args:
        tenant_id: Tenant UUID string.
        provider: Provider used as the Findings attachment point.
        report: Parsed Trivy JSON.
        mode: Hub mode label stored in scanner_args.
        scan_name: Optional scan display name.
        started_at: When the Trivy CLI run started; sets the scan duration.
        rows: Finding rows already mapped from ``report``; mapped here when
            omitted.

    Returns:
        The created Scan row.
    """
    from api.db_router import MainRouter

    admin = MainRouter.admin_db
    if rows is None:
        rows = report_to_finding_rows(report, mode=mode)
    now = timezone.now()
    name = (scan_name or f"Trivy {mode} {now.strftime('%Y-%m-%d %H:%M')}")[:100]

    with rls_transaction(tenant_id):
        scan = Scan.all_objects.using(admin).create(
            tenant_id=tenant_id,
            provider_id=provider.id,
            name=name,
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            progress=100,
            unique_resource_count=len({row["resource_uid"] for row in rows}),
            started_at=started_at or now,
            completed_at=now,
            duration=int((now - (started_at or now)).total_seconds()),
            scanner_args={"source": "trivy_hub", "mode": mode},
        )

        for row in rows:
            finding = Finding.all_objects.using(admin).create(
                id=uuid7(),
                tenant_id=tenant_id,
                scan=scan,
                uid=row["uid"],
                status=row["status"],
                status_extended=row["status_extended"],
                severity=row["severity"],
                impact=row["impact"],
                check_id=row["check_id"],
                check_metadata=row["check_metadata"],
                raw_result=row["raw_result"],
                resource_regions=row["resource_regions"] or None,
                resource_services=[item for item in row["resource_services"] if item]
                or None,
                resource_types=row["resource_types"] or None,
            )
            resource, _ = Resource.objects.using(admin).get_or_create(
                tenant_id=tenant_id,
                provider_id=provider.id,
                uid=str(row["resource_uid"]),
                defaults={
                    "name": str(row["resource_name"]) or "trivy-resource",
                    "region": (row["resource_regions"] or ["global"])[0] or "global",
                    "service": next(
                        (item for item in row["resource_services"] if item),
                        mode,
                    ),
                    "type": (row["resource_types"] or [mode])[0] or mode,
                },
            )
            ResourceFindingMapping.objects.using(admin).get_or_create(
                tenant_id=tenant_id,
                resource=resource,
                finding=finding,
            )

    return scan
