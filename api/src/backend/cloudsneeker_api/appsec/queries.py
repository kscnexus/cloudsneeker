"""Read side of the ASPM API: filters, serialization and dashboard figures.

Every figure is computed from stored findings, components and runs. Nothing
here returns a constant or an estimate.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from cloudsneeker_api.models import (
    AppSecApplication,
    AppSecComponent,
    AppSecFinding,
    AppSecSbom,
    FindingTriage,
    TrivyRun,
    TrivyTarget,
)
from django.db.models import (
    Case,
    CharField,
    Count,
    IntegerField,
    Max,
    OuterRef,
    Q,
    QuerySet,
    Subquery,
    Value,
    When,
)
from django.db.models.functions import Coalesce, TruncDate

ACTIVE_STATES = ("new", "open", "reopened")
SEVERITIES = ("critical", "high", "medium", "low", "informational", "unknown")
CATEGORIES = ("vulnerability", "misconfiguration", "secret", "license", "code")
# Triage statuses that take a finding out of the work queue.
CLOSED_TRIAGE = ("resolved", "risk_accepted", "false_positive")
MAX_PAGE_SIZE = 100
EXPORT_MAX_ROWS = 20000

FINDING_SORTS = {
    "priority": "priority_score",
    "severity": "severity_rank",
    "last_seen_at": "last_seen_at",
    "first_seen_at": "first_seen_at",
    "rule_id": "rule_id",
    "pkg_name": "pkg_name",
    "due_at": "due_at",
    "title": "title",
}


class QueryError(ValueError):
    """A list parameter is not valid."""


def _csv(value: Any) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _uuids(value: Any, name: str) -> list[str]:
    values = _csv(value)
    for item in values:
        try:
            UUID(item)
        except ValueError:
            raise QueryError(
                f"filter[{name}] takes ids: {item!r} is not one."
            ) from None
    return values


def _bool(value: Any, name: str) -> bool | None:
    if value in (None, ""):
        return None
    text = str(value).lower()
    if text in ("true", "1", "yes"):
        return True
    if text in ("false", "0", "no"):
        return False
    raise QueryError(f"filter[{name}] must be true or false.")


def _choices(params, name: str, allowed: tuple[str, ...]) -> list[str]:
    values = _csv(params.get(f"filter[{name}]"))
    unknown = [item for item in values if item not in allowed]
    if unknown:
        raise QueryError(
            f"filter[{name}] does not accept: {', '.join(unknown)}. "
            f"Use: {', '.join(allowed)}."
        )
    return values


def page_params(params) -> tuple[int, int]:
    """Return ``(page, page_size)`` from ``page[number]`` and ``page[size]``."""

    def positive(name: str, default: int) -> int:
        try:
            value = int(params.get(name) or default)
        except (TypeError, ValueError):
            raise QueryError(f"{name} must be a whole number.") from None
        if value < 1:
            raise QueryError(f"{name} must be 1 or more.")
        return value

    return positive("page[number]", 1), min(positive("page[size]", 25), MAX_PAGE_SIZE)


def severity_rank() -> Case:
    return Case(
        *[
            When(severity=severity, then=Value(len(SEVERITIES) - index))
            for index, severity in enumerate(SEVERITIES)
        ],
        default=Value(0),
        output_field=IntegerField(),
    )


def visible_targets(tenant_id: str, visible_providers: set[str] | None) -> QuerySet:
    queryset = TrivyTarget.objects.filter(tenant_id=tenant_id)
    if visible_providers is not None:
        queryset = queryset.filter(provider_id__in=list(visible_providers))
    return queryset


def findings_queryset(tenant_id: str, visible_providers: set[str] | None) -> QuerySet:
    """Findings a role can read, with ``triage_status`` and ``severity_rank``."""
    queryset = AppSecFinding.objects.filter(tenant_id=tenant_id)
    if visible_providers is not None:
        queryset = queryset.filter(target__provider_id__in=list(visible_providers))
    triage = FindingTriage.objects.filter(
        tenant_id=tenant_id, finding_uid=OuterRef("uid")
    )
    return queryset.annotate(
        triage_status=Coalesce(
            Subquery(triage.values("status")[:1], output_field=CharField()),
            Value("open"),
        ),
        triage_id=Subquery(triage.values("id")[:1]),
        severity_rank=severity_rank(),
    )


def filter_findings(queryset: QuerySet, params, *, now: datetime) -> QuerySet:
    """Apply ``filter[...]`` parameters to a findings queryset.

    Without ``filter[state__in]`` only active findings (new, open, reopened)
    are returned, and without ``filter[suppressed]`` suppressed ones are left
    out, so the default list is the work queue.

    Raises:
        QueryError: Unknown value.
    """
    categories = _choices(params, "category__in", CATEGORIES) or _choices(
        params, "category", CATEGORIES
    )
    if categories:
        queryset = queryset.filter(category__in=categories)
    severities = _choices(params, "severity__in", SEVERITIES)
    if severities:
        queryset = queryset.filter(severity__in=severities)
    states = _choices(params, "state__in", (*ACTIVE_STATES, "fixed"))
    queryset = queryset.filter(state__in=states or ACTIVE_STATES)
    priorities = _choices(params, "priority__in", ("urgent", "high", "medium", "low"))
    if priorities:
        queryset = queryset.filter(priority__in=priorities)
    triage = _choices(
        params,
        "triage_status__in",
        tuple(value for value, _ in FindingTriage.Status.choices),
    )
    if triage:
        queryset = queryset.filter(triage_status__in=triage)
    if params.get("filter[suppressed]") != "any":
        suppressed = _bool(params.get("filter[suppressed]"), "suppressed")
        queryset = queryset.filter(suppressed=bool(suppressed))
    fix = _bool(params.get("filter[fix_available]"), "fix_available")
    if fix is not None:
        queryset = queryset.filter(fix_available=fix)
    overdue = _bool(params.get("filter[overdue]"), "overdue")
    if overdue:
        queryset = queryset.filter(due_at__lt=now).exclude(
            triage_status__in=CLOSED_TRIAGE
        )
    for name, lookup in (
        ("target", "target_id"),
        ("application", "target__application_id"),
        ("run", "last_run_id"),
    ):
        value = params.get(f"filter[{name}]")
        if value:
            queryset = queryset.filter(**{lookup: value})
    # Lists for the multi-select filters (comma-separated ids).
    for name, lookup in (
        ("target__in", "target_id__in"),
        ("application__in", "target__application_id__in"),
    ):
        values = _uuids(params.get(f"filter[{name}]"), name)
        if values:
            queryset = queryset.filter(**{lookup: values})
    for name in ("rule_id", "pkg_name", "ecosystem", "finding_type", "scanner"):
        value = params.get(f"filter[{name}]")
        if value:
            queryset = queryset.filter(**{name: value})
    mode = params.get("filter[target_type]")
    if mode:
        queryset = queryset.filter(target__mode__in=_csv(mode))
    days = params.get("filter[first_seen_days]")
    if days:
        try:
            queryset = queryset.filter(
                first_seen_at__gte=now - timedelta(days=int(days))
            )
        except (TypeError, ValueError):
            raise QueryError(
                "filter[first_seen_days] must be a whole number."
            ) from None
    search = str(params.get("filter[search]") or "").strip()
    if search:
        queryset = queryset.filter(
            Q(title__icontains=search)
            | Q(rule_id__icontains=search)
            | Q(pkg_name__icontains=search)
            | Q(file_path__icontains=search)
            | Q(resource__icontains=search)
        )
    return queryset


def sort_findings(queryset: QuerySet, sort: Any) -> QuerySet:
    """Order by ``sort`` (comma separated, ``-`` reverses); default priority."""
    fields = []
    for item in _csv(sort) or ["-priority"]:
        descending = item.startswith("-")
        column = FINDING_SORTS.get(item.lstrip("-"))
        if column is None:
            raise QueryError(
                f"Cannot sort by {item}. Use: {', '.join(sorted(FINDING_SORTS))}."
            )
        fields.append(f"-{column}" if descending else column)
    return queryset.order_by(*fields, "id")


def _iso(value) -> str | None:
    return value.isoformat() if value else None


def finding_row(finding, *, detail: bool = False) -> dict[str, Any]:
    """Attributes of a finding for the API."""
    row = {
        "uid": finding.uid,
        "category": finding.category,
        "finding_type": finding.finding_type,
        "scanner": finding.scanner,
        "title": finding.title,
        "severity": finding.severity,
        "source_severity": finding.source_severity,
        "priority": finding.priority,
        "priority_score": finding.priority_score,
        "state": finding.state,
        "triage_status": getattr(finding, "triage_status", "open"),
        "rule_id": finding.rule_id,
        "pkg_name": finding.pkg_name,
        "pkg_version": finding.pkg_version,
        "fixed_version": finding.fixed_version,
        "ecosystem": finding.ecosystem,
        "location": finding.location,
        "file_path": finding.file_path,
        "start_line": finding.start_line,
        "end_line": finding.end_line,
        "resource": finding.resource,
        "cvss_score": finding.cvss_score,
        "fix_available": finding.fix_available,
        "suppressed": finding.suppressed,
        "first_seen_at": _iso(finding.first_seen_at),
        "last_seen_at": _iso(finding.last_seen_at),
        "fixed_at": _iso(finding.fixed_at),
        "due_at": _iso(finding.due_at),
        "reopen_count": finding.reopen_count,
        "target_id": str(finding.target_id),
        "target_name": finding.target.name,
        # Empty: the target scans its repository's default branch.
        "target_branch": str((finding.target.config or {}).get("branch") or ""),
        "target_type": finding.target.mode,
        "application_id": (
            str(finding.target.application_id)
            if finding.target.application_id
            else None
        ),
        "application_name": (
            finding.target.application.name if finding.target.application_id else None
        ),
    }
    if detail:
        row.update(
            description=finding.description,
            purl=finding.purl,
            primary_url=finding.primary_url,
            epss_score=finding.epss_score,
            known_exploited=finding.known_exploited,
            suppression=finding.suppression,
            priority_factors=finding.priority_factors,
            details=finding.details,
            first_run_id=str(finding.first_run_id) if finding.first_run_id else None,
            last_run_id=str(finding.last_run_id) if finding.last_run_id else None,
            triage_id=str(finding.triage_id)
            if getattr(finding, "triage_id", None)
            else None,
        )
    return row


def _count_by(queryset: QuerySet, field: str) -> dict[str, int]:
    return {
        str(row[field]): row["count"]
        for row in queryset.values(field).annotate(count=Count("id")).order_by()
    }


def findings_summary(queryset: QuerySet, *, now: datetime) -> dict[str, Any]:
    """Figures for one filtered findings view.

    The vulnerability block keeps its metrics apart: ``instances`` (finding
    rows), ``unique_ids`` (distinct advisories), ``affected_packages``
    (distinct package and ecosystem), ``fixable`` and ``unfixed``.
    """
    active = queryset.filter(state__in=ACTIVE_STATES, suppressed=False)
    vulnerabilities = active.filter(category="vulnerability")
    return {
        "active": active.count(),
        "by_severity": _count_by(active, "severity"),
        "by_category": _count_by(active, "category"),
        "by_priority": _count_by(active, "priority"),
        "by_state": _count_by(queryset.filter(suppressed=False), "state"),
        "by_triage_status": _count_by(active, "triage_status"),
        "suppressed": queryset.filter(suppressed=True, state__in=ACTIVE_STATES).count(),
        "overdue": active.filter(due_at__lt=now)
        .exclude(triage_status__in=CLOSED_TRIAGE)
        .count(),
        "vulnerabilities": {
            "instances": vulnerabilities.count(),
            "unique_ids": vulnerabilities.values("rule_id").distinct().count(),
            "affected_packages": vulnerabilities.values("pkg_name", "ecosystem")
            .distinct()
            .count(),
            "fixable": vulnerabilities.filter(fix_available=True).count(),
            "unfixed": vulnerabilities.filter(fix_available=False).count(),
        },
    }


def latest_sbom_ids(tenant_id: str, targets: QuerySet) -> list[str]:
    """Id of the newest SBOM of each target."""
    newest = (
        AppSecSbom.objects.filter(tenant_id=tenant_id, target_id=OuterRef("pk"))
        .order_by("-version")
        .values("id")[:1]
    )
    return [
        str(value)
        for value in targets.annotate(sbom_id=Subquery(newest)).values_list(
            "sbom_id", flat=True
        )
        if value
    ]


def overview(
    tenant_id: str, visible_providers: set[str] | None, *, now: datetime, days: int = 30
) -> dict[str, Any]:
    """Figures for the Application Security overview."""
    targets = visible_targets(tenant_id, visible_providers)
    findings = findings_queryset(tenant_id, visible_providers)
    active = findings.filter(state__in=ACTIVE_STATES, suppressed=False)
    runs = TrivyRun.objects.filter(tenant_id=tenant_id, target__in=targets)
    since = now - timedelta(days=days)

    target_total = targets.count()
    scanned_targets = (
        runs.filter(status="completed").values("target_id").distinct().count()
    )
    sbom_ids = latest_sbom_ids(tenant_id, targets)
    components = AppSecComponent.objects.filter(
        tenant_id=tenant_id, sbom_id__in=sbom_ids
    )

    def per_day(queryset: QuerySet, field: str) -> dict[str, int]:
        rows = (
            queryset.filter(**{f"{field}__gte": since})
            .annotate(day=TruncDate(field))
            .values("day")
            .annotate(count=Count("id"))
            .order_by("day")
        )
        return {row["day"].isoformat(): row["count"] for row in rows}

    detected = per_day(findings.filter(suppressed=False), "first_seen_at")
    fixed = per_day(findings.filter(state="fixed"), "fixed_at")
    scans = per_day(runs, "inserted_at")
    failed_scans = per_day(runs.filter(status="failed"), "inserted_at")
    trend = []
    for offset in range(days, -1, -1):
        day = (now - timedelta(days=offset)).date().isoformat()
        trend.append(
            {
                "date": day,
                "detected": detected.get(day, 0),
                "fixed": fixed.get(day, 0),
                "scans": scans.get(day, 0),
                "failed_scans": failed_scans.get(day, 0),
            }
        )

    top_targets = list(
        active.values(
            "target_id", "target__name", "target__mode", "target__application__name"
        )
        .annotate(
            total=Count("id"),
            critical=Count("id", filter=Q(severity="critical")),
            high=Count("id", filter=Q(severity="high")),
            urgent=Count("id", filter=Q(priority="urgent")),
            top_score=Max("priority_score"),
        )
        .order_by("-urgent", "-critical", "-high", "-total")[:8]
    )
    top_packages = list(
        active.filter(category="vulnerability")
        .exclude(pkg_name="")
        .values("pkg_name", "ecosystem")
        .annotate(
            vulnerabilities=Count("rule_id", distinct=True),
            targets=Count("target_id", distinct=True),
            critical=Count("id", filter=Q(severity="critical")),
            high=Count("id", filter=Q(severity="high")),
        )
        .order_by("-critical", "-high", "-vulnerabilities")[:8]
    )
    fixed_recent = findings.filter(state="fixed", fixed_at__gte=since)
    durations = [
        (row["fixed_at"] - row["first_seen_at"]).total_seconds() / 86400
        for row in fixed_recent.values("fixed_at", "first_seen_at")[:5000]
    ]
    last_run = (
        runs.order_by("-inserted_at").values("id", "status", "inserted_at").first()
    )

    return {
        "generated_at": now.isoformat(),
        "window_days": days,
        "inventory": {
            "applications": AppSecApplication.objects.filter(
                tenant_id=tenant_id
            ).count(),
            "targets": target_total,
            "scanned_targets": scanned_targets,
            "targets_by_type": _count_by(targets, "mode"),
            "unassigned_targets": targets.filter(application__isnull=True).count(),
        },
        "scans": {
            "total": runs.count(),
            "by_status": _count_by(runs, "status"),
            "last": (
                {
                    "id": str(last_run["id"]),
                    "status": last_run["status"],
                    "at": last_run["inserted_at"].isoformat(),
                }
                if last_run
                else None
            ),
        },
        "findings": findings_summary(findings, now=now),
        "fixed_in_window": fixed_recent.count(),
        "mean_days_to_fix": (
            round(sum(durations) / len(durations), 1) if durations else None
        ),
        "components": {
            "total": components.count(),
            "vulnerable": components.filter(vulnerability_count__gt=0).count(),
            "by_ecosystem": dict(
                sorted(
                    _count_by(components, "ecosystem").items(),
                    key=lambda item: -item[1],
                )[:12]
            ),
            "targets_with_sbom": len(sbom_ids),
        },
        "trend": trend,
        "top_targets": [
            {
                "target_id": str(row["target_id"]),
                "name": row["target__name"],
                "target_type": row["target__mode"],
                "application": row["target__application__name"],
                "total": row["total"],
                "critical": row["critical"],
                "high": row["high"],
                "urgent": row["urgent"],
                "top_score": row["top_score"],
            }
            for row in top_targets
        ],
        "top_packages": top_packages,
    }


def application_stats(
    tenant_id: str, application_ids: list[str], visible_providers: set[str] | None
) -> dict[str, dict[str, Any]]:
    """Per-application figures for the inventory list."""
    stats: dict[str, dict[str, Any]] = {
        str(pk): {
            "targets": 0,
            "target_types": [],
            "active_findings": 0,
            "critical": 0,
            "high": 0,
            "urgent": 0,
            "risk_score": 0,
            "last_scan_at": None,
            "last_scan_status": None,
            "sbom_targets": 0,
        }
        for pk in application_ids
    }
    if not application_ids:
        return stats
    targets = visible_targets(tenant_id, visible_providers).filter(
        application_id__in=application_ids
    )
    newest_run = TrivyRun.objects.filter(
        tenant_id=tenant_id, target_id=OuterRef("pk")
    ).order_by("-inserted_at")
    has_sbom = AppSecSbom.objects.filter(tenant_id=tenant_id, target_id=OuterRef("pk"))
    for row in targets.annotate(
        last_at=Subquery(newest_run.values("inserted_at")[:1]),
        last_status=Subquery(newest_run.values("status")[:1]),
        sbom=Subquery(has_sbom.values("id")[:1]),
    ).values("application_id", "mode", "last_at", "last_status", "sbom"):
        entry = stats[str(row["application_id"])]
        entry["targets"] += 1
        if row["mode"] not in entry["target_types"]:
            entry["target_types"].append(row["mode"])
        if row["sbom"]:
            entry["sbom_targets"] += 1
        if row["last_at"] and (
            entry["last_scan_at"] is None
            or row["last_at"].isoformat() > entry["last_scan_at"]
        ):
            entry["last_scan_at"] = row["last_at"].isoformat()
            entry["last_scan_status"] = row["last_status"]
    active = findings_queryset(tenant_id, visible_providers).filter(
        target__application_id__in=application_ids,
        state__in=ACTIVE_STATES,
        suppressed=False,
    )
    for row in active.values("target__application_id").annotate(
        total=Count("id"),
        critical=Count("id", filter=Q(severity="critical")),
        high=Count("id", filter=Q(severity="high")),
        urgent=Count("id", filter=Q(priority="urgent")),
        top=Max("priority_score"),
    ):
        entry = stats[str(row["target__application_id"])]
        entry.update(
            active_findings=row["total"],
            critical=row["critical"],
            high=row["high"],
            urgent=row["urgent"],
            # The application is as exposed as its worst open finding.
            risk_score=row["top"] or 0,
        )
    return stats
