"""Import CLI OCSF finding reports into Finding rows."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from api.db_utils import rls_transaction
from api.models import Finding, Provider, Resource, ResourceFindingMapping, Scan, StateChoices
from cloudsneeker_api.models import FindingIngestion
from django.utils import timezone
from uuid6 import uuid7

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "info": "informational",
    "unknown": "low",
}


def parse_ocsf_payload(raw: bytes | str) -> list[dict[str, Any]]:
    """Parse an OCSF JSON array or NDJSON finding report."""
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    text = text.strip()
    if not text:
        raise ValueError("The report is empty.")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        records = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
        parsed = records
    if isinstance(parsed, dict):
        parsed = [parsed]
    if not isinstance(parsed, list) or not parsed:
        raise ValueError("The report is not a valid OCSF finding report.")
    if not all(isinstance(item, dict) for item in parsed):
        raise ValueError("The report is not a valid OCSF finding report.")
    return parsed


def _finding_fields(record: dict[str, Any]) -> dict[str, Any] | None:
    finding_info = record.get("finding_info") or {}
    resources = record.get("resources") or []
    resource = resources[0] if resources else {}
    cloud = record.get("cloud") or {}
    account = cloud.get("account") or {}
    status_code = str(record.get("status_code") or record.get("status") or "FAIL").upper()
    if status_code not in {"FAIL", "PASS", "MANUAL"}:
        status_code = "FAIL"
    severity_raw = str(record.get("severity") or "medium").lower()
    severity = SEVERITY_MAP.get(severity_raw, "medium")
    check_id = (
        (finding_info.get("analytic") or {}).get("uid")
        or finding_info.get("uid")
        or record.get("unmapped", {}).get("check_id")
        or "imported-check"
    )
    uid = finding_info.get("uid") or f"imported-{uuid4()}"
    return {
        "uid": str(uid)[:300],
        "status": status_code,
        "status_extended": record.get("message") or finding_info.get("desc") or "",
        "severity": severity,
        "impact": severity,
        "check_id": str(check_id)[:100],
        "check_metadata": {
            "CheckTitle": finding_info.get("title") or finding_info.get("name") or check_id,
            "Description": finding_info.get("desc") or "",
            "Severity": severity,
            "Provider": cloud.get("provider") or account.get("type") or "aws",
            "ServiceName": (resource.get("group") or {}).get("name")
            if isinstance(resource.get("group"), dict)
            else resource.get("group") or "",
            "ResourceType": resource.get("type") or "",
        },
        "raw_result": record,
        "resource_regions": [resource["region"]] if resource.get("region") else [],
        "resource_services": [
            (resource.get("group") or {}).get("name")
            if isinstance(resource.get("group"), dict)
            else resource.get("group")
        ]
        if resource.get("group")
        else [],
        "resource_types": [resource["type"]] if resource.get("type") else [],
        "resource_uid": resource.get("uid") or resource.get("name") or uid,
        "resource_name": resource.get("name") or resource.get("uid") or "imported-resource",
        "provider_uid": account.get("uid") or cloud.get("account_uid") or "",
        "provider_type": str(cloud.get("provider") or "aws").lower(),
    }


def process_ingestion(tenant_id: str, ingestion_id: str) -> FindingIngestion:
    """Create an imported scan and Finding rows from a stored OCSF payload."""
    from django.db import DEFAULT_DB_ALIAS

    with rls_transaction(tenant_id, using=DEFAULT_DB_ALIAS):
        ingestion = FindingIngestion.objects.using(DEFAULT_DB_ALIAS).get(
            id=ingestion_id, tenant_id=tenant_id
        )
        ingestion.status = FindingIngestion.Status.PROCESSING
        ingestion.save(update_fields=["status", "updated_at"])

        records = ingestion.payload if isinstance(ingestion.payload, list) else []
        ingestion.total_records = len(records)
        processed = 0
        invalid = 0
        first_fields = None
        finding_rows: list[dict[str, Any]] = []

        for record in records:
            try:
                fields = _finding_fields(record)
            except Exception:  # noqa: BLE001
                fields = None
            if not fields:
                invalid += 1
                continue
            if first_fields is None:
                first_fields = fields
            finding_rows.append(fields)
            processed += 1

        if not finding_rows or first_fields is None:
            ingestion.status = FindingIngestion.Status.FAILED
            ingestion.processed_records = processed
            ingestion.invalid_records = invalid
            ingestion.error_message = "No valid findings were found in the report."
            ingestion.save()
            return ingestion

        provider = None
        if first_fields["provider_uid"]:
            provider = Provider.objects.filter(
                tenant_id=tenant_id, uid=first_fields["provider_uid"]
            ).first()
        if provider is None:
            provider = Provider.objects.filter(tenant_id=tenant_id).first()
        if provider is None:
            ingestion.status = FindingIngestion.Status.FAILED
            ingestion.error_message = (
                "Add a provider before importing findings so the report can be attached."
            )
            ingestion.processed_records = processed
            ingestion.invalid_records = invalid
            ingestion.save()
            return ingestion

        now = timezone.now()
        # Imported scans are intentionally outside LIVE_SCAN_TRIGGERS.
        scan = Scan.all_objects.create(
            tenant_id=tenant_id,
            provider=provider,
            name=f"CLI Import {now.strftime('%Y-%m-%d %H:%M')}"[:100],
            trigger=Scan.TriggerChoices.MANUAL,
            state=StateChoices.COMPLETED,
            progress=100,
            unique_resource_count=len({row["resource_uid"] for row in finding_rows}),
            started_at=now,
            completed_at=now,
            scanner_args={"source": "cli_import", "imported": True},
        )

        for row in finding_rows:
            finding = Finding.all_objects.create(
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
            resource, _ = Resource.objects.get_or_create(
                tenant_id=tenant_id,
                provider=provider,
                uid=str(row["resource_uid"]),
                defaults={
                    "name": str(row["resource_name"]) or "imported-resource",
                    "region": (row["resource_regions"] or ["global"])[0] or "global",
                    "service": next(
                        (item for item in row["resource_services"] if item),
                        "imported",
                    ),
                    "type": (row["resource_types"] or ["resource"])[0] or "resource",
                },
            )
            ResourceFindingMapping.objects.get_or_create(
                tenant_id=tenant_id,
                resource=resource,
                finding=finding,
            )

        ingestion.status = FindingIngestion.Status.COMPLETED
        ingestion.processed_records = processed
        ingestion.invalid_records = invalid
        ingestion.scan_id = scan.id
        ingestion.error_message = ""
        ingestion.save()
        return ingestion
