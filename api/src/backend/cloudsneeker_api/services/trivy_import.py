"""Import Trivy JSON reports into shared Scan / Finding rows."""

from __future__ import annotations

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


def _normalize_severity(raw: str | None) -> str:
    key = str(raw or "MEDIUM").upper()
    return SEVERITY_MAP.get(key, "medium")


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
) -> Scan:
    """Create a completed Scan and Finding rows from a Trivy JSON report.

    Args:
        tenant_id: Tenant UUID string.
        provider: Provider used as the Findings attachment point.
        report: Parsed Trivy JSON.
        mode: Hub mode label stored in scanner_args.
        scan_name: Optional scan display name.
        started_at: When the Trivy CLI run started; sets the scan duration.

    Returns:
        The created Scan row.
    """
    from api.db_router import MainRouter

    admin = MainRouter.admin_db
    rows = trivy_results_to_finding_rows(report, mode=mode)
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
