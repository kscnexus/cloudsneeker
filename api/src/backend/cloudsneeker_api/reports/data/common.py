"""Shared queries and scoring used by every report data assembler.

All functions expect to run inside ``rls_transaction(tenant_id)`` and filter
by ``tenant_id`` explicitly as well, so they are safe on the admin alias too.

Scan scoping:

* Cloud scans are engine scans of cloud providers (every provider type
  except the application security types ``iac`` and ``image``) that did not
  come from Trivy Hub. The latest per provider comes from upstream
  ``ScanQuerySet.latest_ids_per_provider``.
* Application security scans are Trivy Hub scans
  (``scanner_args.source == "trivy_hub"``, mode in ``scanner_args.mode``) and
  engine scans of ``iac`` / ``image`` providers. A provider can feed several
  modes, so the latest scan is kept per ``(provider, mode)`` stream; a plain
  engine scan of an IaC or image provider counts as the ``iac`` / ``image``
  stream, the same one a Trivy Hub ``iac`` / ``image`` target feeds.
"""

from __future__ import annotations

import os
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable
from uuid import UUID

from api.models import (
    ComplianceOverviewSummary,
    ComplianceRequirementOverview,
    Finding,
    Provider,
    ResourceFindingMapping,
    Scan,
    StateChoices,
)
from cloudsneeker_api.reports.schema import (
    SEVERITY_ORDER,
    ReportFilters,
    ReportTable,
    empty_severity_counts,
)
from django.db.models import Case, Count, IntegerField, Q, QuerySet, Sum, Value, When

TRIVY_HUB_SOURCE = "trivy_hub"
APPSEC_PROVIDER_TYPES: frozenset[str] = frozenset(
    {Provider.ProviderChoices.IAC.value, Provider.ProviderChoices.IMAGE.value}
)

# Severity weights used by the security score and risk ranking.
SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 0.5,
    "informational": 0.0,
}

# Weighted failures at which an exposure-only score (no PASS results) is 50.
EXPOSURE_HALF_SCORE = 50.0

GRADE_BANDS: tuple[tuple[float, str], ...] = (
    (90.0, "A"),
    (80.0, "B"),
    (70.0, "C"),
    (60.0, "D"),
)

BUSINESS_IMPACT: dict[str, str] = {
    "critical": (
        "Could lead directly to a breach, data loss, or account takeover; "
        "attackers actively look for this class of issue."
    ),
    "high": (
        "Significantly raises the chance of unauthorized access or service "
        "disruption."
    ),
    "medium": (
        "Weakens defenses; combined with other gaps it can be exploited."
    ),
    "low": "Limited direct impact; fix as part of routine hygiene.",
    "informational": "No direct risk; kept for visibility.",
}

VULNERABILITY_Q = (
    Q(check_id__istartswith="CVE-")
    | Q(check_id__istartswith="GHSA-")
    | Q(raw_result__has_key="VulnerabilityID")
)
SECRET_Q = (
    Q(resource_services__contains=["secret"])
    | Q(categories__contains=["secrets"])
    | Q(raw_result__has_key="RuleID")
)

FINDING_COLUMNS: list[tuple[str, str]] = [
    ("severity", "Severity"),
    ("check_id", "Check"),
    ("title", "Title"),
    ("provider", "Source"),
    ("resource", "Resource"),
    ("service", "Service"),
    ("region", "Region"),
    ("first_seen_at", "First seen"),
    ("detail", "Detail"),
]


def max_detail_rows() -> int:
    """Return the per-table row bound for exports (``REPORT_MAX_DETAIL_ROWS``)."""
    try:
        return max(1, int(os.environ.get("REPORT_MAX_DETAIL_ROWS", "5000")))
    except ValueError:
        return 5000


@dataclass(frozen=True)
class ScanScope:
    """Which scans a report reads.

    Attributes:
        cloud: Include engine scans of cloud providers.
        trivy_modes: Trivy Hub modes to include.
        prowler_provider_types: Application security provider types whose
            plain engine scans are included (mapped to the same-named mode).
    """

    cloud: bool = False
    trivy_modes: frozenset[str] = field(default_factory=frozenset)
    prowler_provider_types: frozenset[str] = field(default_factory=frozenset)

    @property
    def has_appsec(self) -> bool:
        """True when the scope reads any application security stream."""
        return bool(self.trivy_modes or self.prowler_provider_types)


CLOUD_SCOPE = ScanScope(cloud=True)


@dataclass
class FindingStats:
    """Aggregated counts over a finding queryset.

    Attributes:
        fail_by_severity: Failed, unmuted findings per severity.
        pass_by_severity: Passed, unmuted findings per severity.
        status: ``pass`` / ``fail`` / ``muted`` / ``manual`` totals.
    """

    fail_by_severity: dict[str, int] = field(default_factory=empty_severity_counts)
    pass_by_severity: dict[str, int] = field(default_factory=empty_severity_counts)
    status: dict[str, int] = field(
        default_factory=lambda: {"pass": 0, "fail": 0, "muted": 0, "manual": 0}
    )

    @property
    def total(self) -> int:
        """All findings counted, including muted and manual ones."""
        return sum(self.status.values())


# ---------------------------------------------------------------------------
# Providers and scans
# ---------------------------------------------------------------------------


def providers_in_scope(tenant_id: str, filters: ReportFilters) -> list[Provider]:
    """Return the non-deleted providers the report covers.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters; ``provider_ids`` narrows the set.

    Returns:
        Providers ordered by type and alias.
    """
    queryset = Provider.objects.filter(tenant_id=tenant_id)
    if filters.provider_ids:
        queryset = queryset.filter(id__in=filters.provider_ids)
    return list(queryset.order_by("provider", "alias", "uid"))


def provider_label(provider: Provider | None) -> str:
    """Return a readable provider label (``alias`` or ``uid``)."""
    if provider is None:
        return "Unknown"
    return str(provider.alias or provider.uid)


def _trivy_q() -> Q:
    return Q(scanner_args__contains={"source": TRIVY_HUB_SOURCE})


def scope_scans(
    tenant_id: str, filters: ReportFilters, scope: ScanScope
) -> QuerySet:
    """Return every completed scan inside the scope and date window.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters.
        scope: Scan scope.

    Returns:
        A ``ScanQuerySet`` (not deduplicated per provider).
    """
    queryset = Scan.all_objects.filter(
        tenant_id=tenant_id,
        state=StateChoices.COMPLETED,
        provider__is_deleted=False,
    )
    if filters.provider_ids:
        queryset = queryset.filter(provider_id__in=filters.provider_ids)
    if filters.date_from:
        queryset = queryset.filter(completed_at__gte=filters.date_from)
    if filters.date_to:
        queryset = queryset.filter(completed_at__lte=filters.date_to)

    parts: list[Q] = []
    if scope.cloud:
        parts.append(
            ~_trivy_q() & ~Q(provider__provider__in=sorted(APPSEC_PROVIDER_TYPES))
        )
    if scope.trivy_modes:
        parts.append(_trivy_q() & Q(scanner_args__mode__in=sorted(scope.trivy_modes)))
    if scope.prowler_provider_types:
        parts.append(
            ~_trivy_q()
            & Q(provider__provider__in=sorted(scope.prowler_provider_types))
        )
    if not parts:
        return queryset.none()
    scope_q = parts[0]
    for part in parts[1:]:
        scope_q |= part
    return queryset.filter(scope_q)


def stream_mode(scanner_args: dict | None, provider_type: str) -> str:
    """Return the stream mode of a scan.

    Trivy Hub scans report their ``scanner_args.mode``; other scans use their
    provider type, so a plain IaC scan and a Trivy Hub ``iac`` target share a
    stream.
    """
    args = scanner_args or {}
    if args.get("source") == TRIVY_HUB_SOURCE and args.get("mode"):
        return str(args["mode"])
    return provider_type


def latest_scan_ids(
    tenant_id: str, filters: ReportFilters, scope: ScanScope
) -> list[UUID]:
    """Return the latest completed scan id per provider (and stream).

    Cloud-only scopes use upstream ``latest_ids_per_provider``. Scopes with
    application security streams keep one scan per ``(provider, mode)``.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters.
        scope: Scan scope.

    Returns:
        Scan ids.
    """
    queryset = scope_scans(tenant_id, filters, scope)
    if not scope.has_appsec:
        return queryset.latest_ids_per_provider()

    picked: dict[tuple[str, str], UUID] = {}
    rows = queryset.latest_first().values_list(
        "id", "provider_id", "provider__provider", "scanner_args"
    )
    for scan_id, provider_id, provider_type, scanner_args in rows.iterator(
        chunk_size=2000
    ):
        key = (str(provider_id), stream_mode(scanner_args, provider_type))
        if key not in picked:
            picked[key] = scan_id
    return list(picked.values())


def scan_streams(scan_ids: Iterable[UUID]) -> list[dict[str, Any]]:
    """Describe scans for the per-source breakdown.

    Args:
        scan_ids: Scan ids (already tenant-scoped by the caller).

    Returns:
        ``{"scan_id", "provider_id", "provider", "provider_type", "mode",
        "completed_at"}`` per scan.
    """
    ids = list(scan_ids)
    if not ids:
        return []
    rows = Scan.all_objects.filter(id__in=ids).values(
        "id",
        "provider_id",
        "provider__alias",
        "provider__uid",
        "provider__provider",
        "scanner_args",
        "completed_at",
    )
    return [
        {
            "scan_id": str(row["id"]),
            "provider_id": str(row["provider_id"]),
            "provider": str(row["provider__alias"] or row["provider__uid"]),
            "provider_type": row["provider__provider"],
            "mode": stream_mode(row["scanner_args"], row["provider__provider"]),
            "completed_at": row["completed_at"],
        }
        for row in rows
    ]


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def findings_for(
    tenant_id: str,
    scan_ids: Iterable[UUID],
    filters: ReportFilters,
    *,
    include_q: Q | None = None,
    exclude_q: Iterable[Q] = (),
) -> QuerySet:
    """Return findings of the given scans with the severity floor applied.

    Args:
        tenant_id: Tenant UUID string.
        scan_ids: Scans to read.
        filters: Report filters (severity floor).
        include_q: Extra condition the finding must match.
        exclude_q: Conditions that drop a finding (applied with ``exclude`` so
            NULL array columns are handled the way Django documents).

    Returns:
        Finding queryset.
    """
    queryset = Finding.all_objects.filter(
        tenant_id=tenant_id, scan_id__in=list(scan_ids)
    )
    severities = filters.severities()
    if len(severities) < len(SEVERITY_ORDER):
        queryset = queryset.filter(severity__in=severities)
    if include_q is not None:
        queryset = queryset.filter(include_q)
    for condition in exclude_q:
        queryset = queryset.exclude(condition)
    return queryset


def aggregate_findings(queryset: QuerySet) -> FindingStats:
    """Count findings by status and severity in one query.

    Args:
        queryset: Finding queryset.

    Returns:
        ``FindingStats`` (muted findings only count towards ``muted``).
    """
    stats = FindingStats()
    rows = queryset.values("status", "severity", "muted").annotate(count=Count("id"))
    for row in rows:
        count = int(row["count"] or 0)
        severity = str(row["severity"])
        status = str(row["status"]).upper()
        if row["muted"]:
            stats.status["muted"] += count
            continue
        if status == "FAIL":
            stats.status["fail"] += count
            if severity in stats.fail_by_severity:
                stats.fail_by_severity[severity] += count
        elif status == "PASS":
            stats.status["pass"] += count
            if severity in stats.pass_by_severity:
                stats.pass_by_severity[severity] += count
        else:
            stats.status["manual"] += count
    return stats


def merge_stats(items: Iterable[FindingStats]) -> FindingStats:
    """Sum several ``FindingStats``."""
    merged = FindingStats()
    for item in items:
        for severity in SEVERITY_ORDER:
            merged.fail_by_severity[severity] += item.fail_by_severity[severity]
            merged.pass_by_severity[severity] += item.pass_by_severity[severity]
        for key in merged.status:
            merged.status[key] += item.status[key]
    return merged


def security_score(
    fail_by_severity: dict[str, int], pass_by_severity: dict[str, int]
) -> float | None:
    """Return a 0-100 security score (higher is better).

    With PASS results (posture data) the score is the severity-weighted pass
    ratio. With failures only (vulnerability or secret data, where scanners
    never emit PASS) it decays with the weighted failure count:
    ``100 / (1 + weighted / EXPOSURE_HALF_SCORE)``.

    Args:
        fail_by_severity: Failed findings per severity.
        pass_by_severity: Passed findings per severity.

    Returns:
        Score rounded to one decimal, or ``None`` with no findings at all.
    """
    weighted_fail = sum(
        SEVERITY_WEIGHTS.get(sev, 0.0) * count for sev, count in fail_by_severity.items()
    )
    weighted_pass = sum(
        SEVERITY_WEIGHTS.get(sev, 0.0) * count for sev, count in pass_by_severity.items()
    )
    total_findings = sum(fail_by_severity.values()) + sum(pass_by_severity.values())
    if total_findings == 0:
        return None
    if weighted_pass > 0:
        return round(100.0 * weighted_pass / (weighted_pass + weighted_fail), 1)
    if weighted_fail == 0:
        return 100.0
    return round(100.0 / (1.0 + weighted_fail / EXPOSURE_HALF_SCORE), 1)


def grade_for(score: float | None) -> str:
    """Map a score to a letter grade (``N/A`` without data)."""
    if score is None:
        return "N/A"
    for floor, grade in GRADE_BANDS:
        if score >= floor:
            return grade
    return "F"


def severity_rank_expression() -> Case:
    """Return an ORDER BY expression that sorts critical first."""
    return Case(
        *[
            When(severity=severity, then=Value(index))
            for index, severity in enumerate(SEVERITY_ORDER)
        ],
        default=Value(len(SEVERITY_ORDER)),
        output_field=IntegerField(),
    )


def _metadata_text(metadata: dict, *keys: str) -> str:
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def remediation_text(metadata: dict, raw_result: dict | None = None) -> str:
    """Return the recommended fix for a finding.

    Reads the check's ``Remediation.Recommendation.Text`` and falls back to the
    Trivy fixed version or a generic sentence.
    """
    remediation = metadata.get("Remediation") or {}
    if isinstance(remediation, dict):
        recommendation = remediation.get("Recommendation") or {}
        if isinstance(recommendation, dict):
            text = recommendation.get("Text")
            if isinstance(text, str) and text.strip():
                return text.strip()
    raw = raw_result or {}
    fixed = raw.get("FixedVersion")
    package = raw.get("PkgName")
    if fixed and package:
        return f"Upgrade {package} to {fixed} or later."
    resolution = raw.get("Resolution")
    if isinstance(resolution, str) and resolution.strip():
        return resolution.strip()
    return "Review the affected resources and apply the vendor-recommended fix."


def business_impact(severity: str, metadata: dict) -> str:
    """Return a plain-language impact sentence for management readers."""
    risk = _metadata_text(metadata, "Risk")
    if risk:
        return risk[:400]
    return BUSINESS_IMPACT.get(severity, BUSINESS_IMPACT["medium"])


def top_risks(queryset: QuerySet, *, limit: int = 10) -> list[dict[str, Any]]:
    """Rank failing checks by severity, impacted resources, and findings.

    Args:
        queryset: Finding queryset (already scoped).
        limit: Maximum risks returned.

    Returns:
        Risk rows ``{"check_id", "title", "severity", "findings", "resources",
        "service", "impact", "remediation"}``.
    """
    rows = (
        queryset.filter(status="FAIL", muted=False)
        .values("check_id", "severity")
        .annotate(
            findings=Count("id"),
            resources=Count("resources", distinct=True),
        )
    )
    merged: dict[str, dict[str, Any]] = {}
    for row in rows:
        check_id = row["check_id"]
        severity = str(row["severity"])
        entry = merged.setdefault(
            check_id,
            {"check_id": check_id, "severity": severity, "findings": 0, "resources": 0},
        )
        entry["findings"] += int(row["findings"] or 0)
        entry["resources"] += int(row["resources"] or 0)
        if _severity_index(severity) < _severity_index(entry["severity"]):
            entry["severity"] = severity

    ranked = sorted(
        merged.values(),
        key=lambda item: (
            _severity_index(item["severity"]),
            -item["resources"],
            -item["findings"],
            item["check_id"],
        ),
    )[:limit]

    for entry in ranked:
        sample = (
            queryset.filter(check_id=entry["check_id"])
            .values("check_metadata", "raw_result")
            .first()
            or {}
        )
        metadata = sample.get("check_metadata") or {}
        raw_result = sample.get("raw_result") or {}
        entry["title"] = (
            _metadata_text(metadata, "CheckTitle", "Title") or entry["check_id"]
        )
        entry["service"] = _metadata_text(metadata, "ServiceName", "servicename")
        entry["impact"] = business_impact(entry["severity"], metadata)
        entry["remediation"] = remediation_text(metadata, raw_result)
    return ranked


def _severity_index(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


def breakdown_by_scan(
    queryset: QuerySet, streams: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Return per-source rows (one per scan) with failure counts.

    Args:
        queryset: Finding queryset over the streams' scans.
        streams: Output of ``scan_streams``.

    Returns:
        Rows sorted by failed findings, most first.
    """
    counts: dict[str, dict[str, int]] = {}
    rows = (
        queryset.filter(muted=False)
        .values("scan_id", "status", "severity")
        .annotate(count=Count("id"))
    )
    for row in rows:
        bucket = counts.setdefault(
            str(row["scan_id"]),
            {"pass": 0, "fail": 0, **empty_severity_counts()},
        )
        status = str(row["status"]).upper()
        count = int(row["count"] or 0)
        if status == "FAIL":
            bucket["fail"] += count
            severity = str(row["severity"])
            if severity in bucket:
                bucket[severity] += count
        elif status == "PASS":
            bucket["pass"] += count

    result = []
    for stream in streams:
        bucket = counts.get(stream["scan_id"], {"pass": 0, "fail": 0, **empty_severity_counts()})
        result.append({**stream, **bucket})
    return sorted(result, key=lambda item: (-item["fail"], item["provider"]))


def breakdown_by_service(queryset: QuerySet, *, limit: int = 15) -> list[dict[str, Any]]:
    """Return failed findings per service (first ``resource_services`` entry)."""
    rows = (
        queryset.filter(status="FAIL", muted=False)
        .values("resource_services")
        .annotate(count=Count("id"))
    )
    totals: dict[str, int] = {}
    for row in rows:
        services = row["resource_services"] or ["other"]
        service = str(services[0] or "other")
        totals[service] = totals.get(service, 0) + int(row["count"] or 0)
    ordered = sorted(totals.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return [{"service": service, "fail": count} for service, count in ordered]


def trend(
    tenant_id: str,
    filters: ReportFilters,
    scope: ScanScope,
    *,
    extra_q: Q | None = None,
    exclude_q: Iterable[Q] = (),
) -> list[dict[str, Any]]:
    """Return failed / passed findings for the last N days with scans.

    Each point sums the scans completed that day, so a day with several
    providers shows their combined result.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters (``trend_points`` bounds the series).
        scope: Scan scope.
        extra_q: Finding condition (same as the report's).
        exclude_q: Finding exclusions (same as the report's).

    Returns:
        Points ordered oldest first:
        ``{"date", "fail", "pass", "critical", "high"}``.
    """
    scan_rows = (
        scope_scans(tenant_id, filters, scope)
        .exclude(completed_at__isnull=True)
        .order_by("-completed_at")
        .values_list("id", "completed_at")[: filters.trend_points * 50]
    )
    by_day: OrderedDict[str, list[UUID]] = OrderedDict()
    for scan_id, completed_at in scan_rows:
        day = completed_at.date().isoformat()
        if day not in by_day and len(by_day) >= filters.trend_points:
            break
        by_day.setdefault(day, []).append(scan_id)
    if not by_day:
        return []

    day_of_scan = {
        str(scan_id): day for day, scan_ids in by_day.items() for scan_id in scan_ids
    }
    queryset = findings_for(
        tenant_id,
        list(day_of_scan),
        filters,
        include_q=extra_q,
        exclude_q=exclude_q,
    ).filter(muted=False)
    points = {
        day: {"date": day, "fail": 0, "pass": 0, "critical": 0, "high": 0}
        for day in by_day
    }
    for row in queryset.values("scan_id", "status", "severity").annotate(
        count=Count("id")
    ):
        point = points[day_of_scan[str(row["scan_id"])]]
        count = int(row["count"] or 0)
        status = str(row["status"]).upper()
        if status == "FAIL":
            point["fail"] += count
            if str(row["severity"]) in ("critical", "high"):
                point[str(row["severity"])] += count
        elif status == "PASS":
            point["pass"] += count
    return [points[day] for day in sorted(points)]


def compliance_posture(
    tenant_id: str, scan_ids: Iterable[UUID]
) -> list[dict[str, Any]]:
    """Return pass percentage per framework across the given scans.

    Reads the pre-aggregated ``ComplianceOverviewSummary`` rows and falls back
    to ``ComplianceRequirementOverview`` for scans that have none.

    Args:
        tenant_id: Tenant UUID string.
        scan_ids: Scans to read.

    Returns:
        Rows ``{"compliance_id", "passed", "failed", "manual", "total",
        "pass_pct"}`` sorted by ``pass_pct`` ascending (weakest first).
    """
    ids = list(scan_ids)
    if not ids:
        return []
    totals: dict[str, dict[str, int]] = {}
    summarized_scans: set[str] = set()
    summaries = (
        ComplianceOverviewSummary.objects.filter(tenant_id=tenant_id, scan_id__in=ids)
        .values("compliance_id", "scan_id")
        .annotate(
            passed=Sum("requirements_passed"),
            failed=Sum("requirements_failed"),
            manual=Sum("requirements_manual"),
            total=Sum("total_requirements"),
        )
    )
    for row in summaries:
        summarized_scans.add(str(row["scan_id"]))
        bucket = totals.setdefault(
            row["compliance_id"], {"passed": 0, "failed": 0, "manual": 0, "total": 0}
        )
        for key in bucket:
            bucket[key] += int(row[key] or 0)

    missing = [scan_id for scan_id in ids if str(scan_id) not in summarized_scans]
    if missing:
        statuses: dict[tuple[str, str, str], set[str]] = {}
        for row in ComplianceRequirementOverview.objects.filter(
            tenant_id=tenant_id, scan_id__in=missing
        ).values_list("compliance_id", "scan_id", "requirement_id", "requirement_status"):
            compliance_id, scan_id, requirement_id, status = row
            statuses.setdefault((compliance_id, str(scan_id), requirement_id), set()).add(
                str(status).upper()
            )
        for (compliance_id, _scan, _req), values in statuses.items():
            bucket = totals.setdefault(
                compliance_id, {"passed": 0, "failed": 0, "manual": 0, "total": 0}
            )
            bucket["total"] += 1
            status = requirement_status(values)
            if status == "FAIL":
                bucket["failed"] += 1
            elif status == "PASS":
                bucket["passed"] += 1
            else:
                bucket["manual"] += 1

    result = []
    for compliance_id, bucket in totals.items():
        scored = bucket["passed"] + bucket["failed"]
        pass_pct = round(100.0 * bucket["passed"] / scored, 1) if scored else None
        result.append({"compliance_id": compliance_id, **bucket, "pass_pct": pass_pct})
    return sorted(
        result,
        key=lambda item: (
            item["pass_pct"] if item["pass_pct"] is not None else 101.0,
            item["compliance_id"],
        ),
    )


def requirement_status(statuses: Iterable[str]) -> str:
    """Combine per-region requirement statuses: any FAIL fails, all PASS pass."""
    values = {str(value).upper() for value in statuses}
    if "FAIL" in values:
        return "FAIL"
    if values and values <= {"PASS"}:
        return "PASS"
    return "MANUAL"


def average_pass_pct(posture: list[dict[str, Any]]) -> float | None:
    """Average ``pass_pct`` over frameworks that have scored requirements."""
    values = [item["pass_pct"] for item in posture if item["pass_pct"] is not None]
    if not values:
        return None
    return round(sum(values) / len(values), 1)


# ---------------------------------------------------------------------------
# Detail rows
# ---------------------------------------------------------------------------


def finding_rows(
    queryset: QuerySet,
    *,
    limit: int | None = None,
    row_builder=None,
) -> tuple[list[dict[str, Any]], int]:
    """Return failed, unmuted findings as table rows (critical first).

    Args:
        queryset: Finding queryset.
        limit: Row bound (defaults to ``max_detail_rows()``).
        row_builder: ``callable(finding_values, resource, provider) -> dict``;
            defaults to ``default_finding_row``.

    Returns:
        ``(rows, total)`` where ``total`` counts every matching finding.
    """
    bound = limit or max_detail_rows()
    failing = queryset.filter(status="FAIL", muted=False)
    total = failing.count()
    values = list(
        failing.annotate(cs_severity_rank=severity_rank_expression())
        .order_by("cs_severity_rank", "check_id", "id")
        .values(
            "id",
            "uid",
            "check_id",
            "severity",
            "status",
            "status_extended",
            "check_metadata",
            "raw_result",
            "resource_regions",
            "resource_services",
            "first_seen_at",
            "inserted_at",
            "scan__provider__alias",
            "scan__provider__uid",
            "scan__provider__provider",
            "scan__scanner_args",
        )[:bound]
    )
    resources = _resources_for([item["id"] for item in values])
    builder = row_builder or default_finding_row
    rows = [builder(item, resources.get(str(item["id"]), {})) for item in values]
    return rows, total


def _resources_for(finding_ids: list[UUID]) -> dict[str, dict[str, str]]:
    if not finding_ids:
        return {}
    result: dict[str, dict[str, str]] = {}
    mappings = ResourceFindingMapping.objects.filter(
        finding_id__in=finding_ids
    ).values(
        "finding_id",
        "resource__uid",
        "resource__name",
        "resource__region",
        "resource__service",
    )
    for row in mappings:
        result.setdefault(
            str(row["finding_id"]),
            {
                "uid": row["resource__uid"] or "",
                "name": row["resource__name"] or "",
                "region": row["resource__region"] or "",
                "service": row["resource__service"] or "",
            },
        )
    return result


def _first(values: list | None) -> str:
    if values:
        return str(values[0] or "")
    return ""


def _short_date(value: datetime | None) -> str:
    return value.date().isoformat() if value else ""


def source_label(item: dict[str, Any]) -> str:
    """Return ``"<provider> (<mode>)"`` for a finding values row."""
    provider = str(item.get("scan__provider__alias") or item.get("scan__provider__uid") or "")
    mode = stream_mode(item.get("scan__scanner_args"), item.get("scan__provider__provider") or "")
    return f"{provider} ({mode})" if mode else provider


def default_finding_row(item: dict[str, Any], resource: dict[str, str]) -> dict[str, Any]:
    """Build a generic finding row for ``FINDING_COLUMNS``."""
    metadata = item.get("check_metadata") or {}
    return {
        "severity": str(item["severity"]),
        "check_id": item["check_id"],
        "title": _metadata_text(metadata, "CheckTitle", "Title") or item["check_id"],
        "provider": source_label(item),
        "resource": resource.get("name") or resource.get("uid") or "",
        "service": resource.get("service") or _first(item.get("resource_services")),
        "region": resource.get("region") or _first(item.get("resource_regions")),
        "first_seen_at": _short_date(item.get("first_seen_at") or item.get("inserted_at")),
        "detail": str(item.get("status_extended") or "")[:500],
    }


def findings_table(
    key: str, title: str, queryset: QuerySet, *, columns=None, row_builder=None
) -> ReportTable:
    """Build a bounded findings ``ReportTable``."""
    rows, total = finding_rows(queryset, row_builder=row_builder)
    return ReportTable(
        key=key,
        title=title,
        columns=list(columns or FINDING_COLUMNS),
        rows=rows,
        total=total,
        truncated=len(rows) < total,
    )


def risk_table(risks: list[dict[str, Any]]) -> ReportTable:
    """Build the top-risks ``ReportTable``."""
    columns = [
        ("severity", "Severity"),
        ("title", "Risk"),
        ("check_id", "Check"),
        ("resources", "Resources"),
        ("findings", "Findings"),
        ("remediation", "Recommended fix"),
    ]
    return ReportTable(
        key="top_risks",
        title="Top risks",
        columns=columns,
        rows=risks,
        total=len(risks),
    )


def remediation_priorities(risks: list[dict[str, Any]], *, limit: int = 10) -> list[dict[str, Any]]:
    """Turn ranked risks into an ordered action list."""
    actions = []
    for index, risk in enumerate(risks[:limit], start=1):
        actions.append(
            {
                "priority": index,
                "action": risk.get("remediation") or "",
                "check_id": risk["check_id"],
                "title": risk.get("title") or risk["check_id"],
                "severity": risk["severity"],
                "resources": risk.get("resources", 0),
            }
        )
    return actions


def severity_kpis(stats: FindingStats) -> dict[str, Any]:
    """Return the shared KPI block for a ``FindingStats``."""
    return {
        "failed_findings": stats.status["fail"],
        "passed_findings": stats.status["pass"],
        "muted_findings": stats.status["muted"],
        "critical": stats.fail_by_severity["critical"],
        "high": stats.fail_by_severity["high"],
    }
