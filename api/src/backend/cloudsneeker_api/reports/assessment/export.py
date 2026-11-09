"""CSV and JSON exports of an assessment report.

The CSV has one row per unique non-passing finding (open, muted, manual, or
unknown status) with the source record id and every merged duplicate id, so
each row traces back to the stored scanner record. Passed results are counted
in the report but not listed. The JSON export is the report payload (content,
scores, coverage, quality) written by the shared JSON renderer.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from cloudsneeker_api.reports.assessment.model import (
    AREA_LABELS,
    CATEGORY_LABELS,
    NormalizedFinding,
)
from cloudsneeker_api.reports.assessment.recommend import (
    SLA_DAYS,
    WINDOWS,
    clean_text,
    priority_for,
)
from cloudsneeker_api.reports.schema import ReportData

CSV_COLUMNS: list[tuple[str, str]] = [
    ("ref", "Ref"),
    ("source_record_id", "Source record id"),
    ("merged_record_ids", "Merged duplicate record ids"),
    ("finding_uid", "Finding UID"),
    ("scan_id", "Scan or run id"),
    ("area", "Area"),
    ("category", "Category"),
    ("scanner", "Scanner stream"),
    ("provider_type", "Provider type"),
    ("provider_id", "Provider id"),
    ("provider", "Provider"),
    ("account", "Account or target"),
    ("resource_uid", "Resource UID"),
    ("resource_name", "Resource name"),
    ("location", "Location"),
    ("region", "Region"),
    ("service", "Service"),
    ("check_id", "Check, rule, or CVE"),
    ("title", "Title"),
    ("severity", "Severity"),
    ("status", "Status"),
    ("muted", "Muted"),
    ("open", "Open"),
    ("triage_status", "Triage status"),
    ("priority", "Priority"),
    ("window", "Roadmap window"),
    ("sla_days", "SLA days"),
    ("fix_available", "Fix available"),
    ("fix_summary", "Fix summary"),
    ("installed_version", "Installed version"),
    ("fixed_version", "Fixed version"),
    ("advisory_cvss", "Advisory-published CVSS"),
    ("first_seen_at", "First seen"),
    ("last_seen_at", "Last seen"),
]


def finding_export_row(finding: NormalizedFinding) -> dict[str, Any]:
    """Flat export row of one finding."""
    priority = priority_for(finding) if finding.is_open else None
    fix = finding.fix or {}
    return {
        "ref": finding.ref,
        "source_record_id": finding.source_id,
        "merged_record_ids": " ".join(finding.duplicate_source_ids),
        "finding_uid": finding.uid,
        "scan_id": finding.scan_id,
        "area": AREA_LABELS.get(finding.area, finding.area),
        "category": CATEGORY_LABELS.get(finding.category, finding.category),
        "scanner": finding.scanner,
        "provider_type": finding.provider_type,
        "provider_id": finding.provider_id,
        "provider": finding.provider_label,
        "account": finding.account,
        "resource_uid": finding.resource_uid,
        "resource_name": finding.resource_name,
        "location": finding.location,
        "region": finding.region,
        "service": finding.service,
        "check_id": finding.check_id,
        "title": clean_text(finding.title, limit=300),
        "severity": finding.severity,
        "status": finding.status,
        "muted": "yes" if finding.muted else "no",
        "open": "yes" if finding.is_open else "no",
        "triage_status": finding.triage_status,
        "priority": priority or "",
        "window": WINDOWS[priority]["label"] if priority else "",
        "sla_days": SLA_DAYS.get(priority or "", ""),
        "fix_available": "yes" if fix.get("fix_available") else "no",
        "fix_summary": clean_text(fix.get("fix_summary"), limit=600),
        "installed_version": fix.get("installed_version") or "",
        "fixed_version": fix.get("fixed_version") or "",
        "advisory_cvss": finding.advisory.get("cvss_published", ""),
        "first_seen_at": finding.first_seen_at.isoformat()
        if finding.first_seen_at
        else "",
        "last_seen_at": finding.last_seen_at.isoformat()
        if finding.last_seen_at
        else "",
    }


def _formula_safe(value: Any) -> Any:
    """Neutralize spreadsheet formulas in exported text."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def render_assessment_csv(data: ReportData) -> bytes:
    """Full traceable CSV (UTF-8 with BOM so spreadsheet tools read Unicode)."""
    findings: list[NormalizedFinding] = getattr(data, "assessment_findings", []) or []
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow([header for _, header in CSV_COLUMNS])
    for finding in sorted(findings, key=lambda item: item.ref):
        row = finding_export_row(finding)
        writer.writerow([_formula_safe(row[key]) for key, _ in CSV_COLUMNS])
    return ("﻿" + buffer.getvalue()).encode("utf-8")
