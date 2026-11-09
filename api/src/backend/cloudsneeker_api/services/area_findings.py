"""Area findings: one findings list shape for every product area.

Cloud Security, Application Security and Cloud Governance each list the
findings of their latest completed scan or run per source, normalized to one
row shape with triage merged in (``knowledge-base/area-findings.md``).

* Cloud: upstream ``Finding`` rows of the latest scan per provider that is
  not an Application Security import.
* Application Security: ``Finding`` rows of the latest completed run per
  target (``TrivyRun.scan_id``).
* Governance: resources matched by the latest completed run per policy
  (``services/governance_findings.py``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from api.models import (
    Finding,
    ResourceFindingMapping,
    Role,
    Scan,
    StateChoices,
    StatusChoices,
)
from cloudsneeker_api.models import FindingTriage, TrivyRun
from cloudsneeker_api.reports.access import visible_provider_ids
from cloudsneeker_api.services.finding_fix import (
    FIX_AVAILABLE,
    FIX_FILTER_VALUES,
    empty_fix,
    finding_fix,
)
from cloudsneeker_api.services.finding_triage import (
    APP_SECURITY_SCAN_SOURCE,
    FindingSnapshot,
    effective_status,
    with_note_summary,
)
from cloudsneeker_api.services.governance_findings import (
    GovernanceFinding,
    governance_findings,
)
from cloudsneeker_api.services.plan_catalog import (
    FEATURE_APPLICATION_SECURITY,
    FEATURE_CLOUD_POSTURE,
    FEATURE_GOVERNANCE,
)
from django.db.models import (
    BooleanField,
    Case,
    F,
    IntegerField,
    Q,
    QuerySet,
    Value,
    When,
)
from django.db.models.fields.json import KeyTextTransform

AREA = FindingTriage.Area
AREA_VALUES = tuple(AREA.values)
# Plan feature that unlocks each area's findings.
AREA_FEATURE = {
    AREA.CLOUD: FEATURE_CLOUD_POSTURE,
    AREA.APPLICATION_SECURITY: FEATURE_APPLICATION_SECURITY,
    AREA.GOVERNANCE: FEATURE_GOVERNANCE,
}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
SORT_FIELDS = ("severity", "last_seen_at", "first_seen_at", "check_id")
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100
SEARCH_MAX_LENGTH = 200
OPEN = FindingTriage.Status.OPEN


class AreaFindingsError(ValueError):
    """Invalid area findings query."""


@dataclass(frozen=True)
class Source:
    """Where a finding came from: a provider, a target or a policy."""

    kind: str
    id: str
    name: str
    provider_id: str


@dataclass
class AreaFindingQuery:
    """Validated list parameters."""

    area: str
    severities: list[str] = field(default_factory=list)
    triage_statuses: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    search: str = ""
    include_muted: bool = False
    include_passed: bool = False
    # FIX_AVAILABLE, FIX_UNAVAILABLE or "" (any). Cloud and Application
    # Security only; governance rows carry no fix.
    fix: str = ""
    sort: str = "severity"
    descending: bool = False
    page: int = 1
    page_size: int = DEFAULT_PAGE_SIZE


@dataclass
class AreaFindingPage:
    rows: list[dict[str, Any]]
    count: int
    sources: list[Source]


def _csv(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _positive_int(value: Any, default: int) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


def parse_query(params: dict[str, Any]) -> AreaFindingQuery:
    """Build a query from ``filter[...]``, ``sort`` and ``page[...]`` params.

    Raises:
        AreaFindingsError: Unknown area, severity, triage status or sort field.
    """
    area = str(params.get("filter[area]") or "").strip()
    if area not in AREA_VALUES:
        raise AreaFindingsError(
            f"filter[area] must be one of {', '.join(AREA_VALUES)}."
        )
    severities = [value.lower() for value in _csv(params.get("filter[severity__in]"))]
    unknown = sorted(set(severities) - set(SEVERITY_ORDER))
    if unknown:
        raise AreaFindingsError(f"Unknown severity: {', '.join(unknown)}.")
    statuses = _csv(params.get("filter[triage_status__in]"))
    unknown = sorted(set(statuses) - set(FindingTriage.Status.values))
    if unknown:
        raise AreaFindingsError(f"Unknown triage status: {', '.join(unknown)}.")
    fix = str(params.get("filter[fix]") or "").strip()
    if fix and fix not in FIX_FILTER_VALUES:
        raise AreaFindingsError(
            f"filter[fix] must be one of {', '.join(FIX_FILTER_VALUES)}."
        )
    sort = str(params.get("sort") or "severity").strip()
    descending = sort.startswith("-")
    sort = sort.lstrip("-")
    if sort not in SORT_FIELDS:
        raise AreaFindingsError(f"sort must be one of {', '.join(SORT_FIELDS)}.")
    return AreaFindingQuery(
        area=area,
        severities=severities,
        triage_statuses=statuses,
        sources=_csv(params.get("filter[source__in]")),
        search=str(params.get("filter[search]") or "").strip()[:SEARCH_MAX_LENGTH],
        include_muted=str(params.get("filter[muted]") or "") == "include",
        include_passed=str(params.get("filter[status]") or "") == "all",
        fix=fix,
        sort=sort,
        descending=descending,
        page=_positive_int(params.get("page[number]"), 1),
        page_size=min(
            MAX_PAGE_SIZE, _positive_int(params.get("page[size]"), DEFAULT_PAGE_SIZE)
        ),
    )


# --- Sources ------------------------------------------------------------------


def _visible(
    queryset: QuerySet, role: Role, field_name: str = "provider_id"
) -> QuerySet:
    visible = visible_provider_ids(role)
    if visible is None:
        return queryset
    return queryset.filter(**{f"{field_name}__in": list(visible)})


def scan_sources(tenant_id: str, role: Role, area: str) -> dict[str, Source]:
    """Latest completed scan id per source of a ``Finding``-backed area."""
    if area == AREA.APPLICATION_SECURITY:
        runs = (
            _visible(TrivyRun.objects.filter(tenant_id=tenant_id), role)
            .filter(status=TrivyRun.Status.COMPLETED, scan_id__isnull=False)
            .order_by("target_id", F("finished_at").desc(nulls_last=True))
            .distinct("target_id")
            .values("scan_id", "target_id", "target__name", "provider_id")
        )
        return {
            str(row["scan_id"]): Source(
                kind="target",
                id=str(row["target_id"]),
                name=row["target__name"],
                provider_id=str(row["provider_id"]),
            )
            for row in runs
        }
    scans = (
        _visible(Scan.all_objects.filter(tenant_id=tenant_id), role)
        .filter(state=StateChoices.COMPLETED)
        .annotate(cs_scan_source=KeyTextTransform("source", "scanner_args"))
        .filter(
            Q(cs_scan_source__isnull=True) | ~Q(cs_scan_source=APP_SECURITY_SCAN_SOURCE)
        )
        .order_by("provider_id", F("completed_at").desc(nulls_last=True))
        .distinct("provider_id")
        .values("id", "provider_id", "provider__alias", "provider__uid")
    )
    return {
        str(row["id"]): Source(
            kind="provider",
            id=str(row["provider_id"]),
            name=row["provider__alias"] or row["provider__uid"],
            provider_id=str(row["provider_id"]),
        )
        for row in scans
    }


# --- Triage -------------------------------------------------------------------


def _area_triages(tenant_id: str, area: str) -> QuerySet:
    return FindingTriage.objects.filter(tenant_id=tenant_id, area=area)


def _triage_filter_uids(
    tenant_id: str, area: str, statuses: list[str]
) -> tuple[QuerySet, bool]:
    """UIDs to keep (``False``) or to drop (``True``) for a triage filter.

    Untriaged findings count as ``open``, so a filter that includes ``open``
    drops the UIDs triaged to any other status instead.
    """
    triages = _area_triages(tenant_id, area)
    if OPEN in statuses:
        other = set(FindingTriage.Status.values) - set(statuses)
        return triages.filter(status__in=other).values("finding_uid"), True
    return triages.filter(status__in=statuses).values("finding_uid"), False


def _triage_fields(triage: FindingTriage | None, snapshot: FindingSnapshot) -> dict:
    if triage is None:
        return {
            "triage_id": None,
            "triage_status": OPEN,
            "triage_notes_count": 0,
            "triage_latest_note": "",
            "assignee_id": None,
        }
    return {
        "triage_id": str(triage.id),
        "triage_status": effective_status(triage, snapshot),
        "triage_notes_count": int(getattr(triage, "notes_total", 0) or 0),
        "triage_latest_note": getattr(triage, "latest_note_body", "") or "",
        "assignee_id": str(triage.assignee_id) if triage.assignee_id else None,
    }


def _triages_by_uid(tenant_id: str, uids: list[str]) -> dict[str, FindingTriage]:
    if not uids:
        return {}
    return {
        triage.finding_uid: triage
        for triage in with_note_summary(
            FindingTriage.objects.filter(tenant_id=tenant_id, finding_uid__in=uids)
        )
    }


# --- Finding-backed areas -------------------------------------------------------


def _severity_rank() -> Case:
    return Case(
        *[
            When(severity=value, then=Value(rank))
            for rank, value in enumerate(SEVERITY_ORDER)
        ],
        default=Value(len(SEVERITY_ORDER)),
        output_field=IntegerField(),
    )


def _finding_queryset(
    tenant_id: str, query: AreaFindingQuery, sources: dict[str, Source]
) -> QuerySet:
    scan_ids = [
        scan_id
        for scan_id, source in sources.items()
        if not query.sources or source.id in query.sources
    ]
    queryset = Finding.all_objects.filter(tenant_id=tenant_id, scan_id__in=scan_ids)
    if not query.include_passed:
        queryset = queryset.filter(status=StatusChoices.FAIL)
    if not query.include_muted:
        queryset = queryset.filter(muted=False)
    if query.severities:
        queryset = queryset.filter(severity__in=query.severities)
    if query.search:
        queryset = queryset.annotate(
            cs_title=KeyTextTransform("CheckTitle", "check_metadata")
        ).filter(
            Q(check_id__icontains=query.search)
            | Q(cs_title__icontains=query.search)
            | Q(uid__icontains=query.search)
        )
    if query.fix:
        # A CASE, not ~Q: missing JSON keys compare as NULL, and NOT NULL
        # would drop every row from the "no fix" list.
        queryset = queryset.annotate(
            cs_fix_available=Case(
                When(_fix_available_q(), then=Value(True)),
                default=Value(False),
                output_field=BooleanField(),
            )
        ).filter(cs_fix_available=query.fix == FIX_AVAILABLE)
    if query.triage_statuses:
        uids, exclude = _triage_filter_uids(
            tenant_id, query.area, query.triage_statuses
        )
        queryset = (
            queryset.exclude(uid__in=uids) if exclude else queryset.filter(uid__in=uids)
        )
    order = {
        "severity": "severity_rank",
        "last_seen_at": "inserted_at",
        "first_seen_at": "first_seen_at",
        "check_id": "check_id",
    }[query.sort]
    # Severity rank 0 is critical, so ascending lists the most severe first.
    expression = (
        F(order).desc(nulls_last=True)
        if query.descending
        else F(order).asc(nulls_last=True)
    )
    return queryset.annotate(severity_rank=_severity_rank()).order_by(expression, "id")


def _non_empty(lookup: str) -> Q:
    return Q(**{f"{lookup}__isnull": False}) & ~Q(**{lookup: ""})


def _fix_available_q() -> Q:
    """Database form of ``finding_fix(...)["fix_available"]``."""
    return (
        _non_empty("raw_result__FixedVersion")
        | _non_empty("raw_result__Resolution")
        | (Q(raw_result__has_key="RuleID") & Q(raw_result__has_key="Match"))
        | (
            Q(raw_result__has_key="Name")
            & Q(raw_result__has_key="Category")
            & ~Q(raw_result__has_key="RuleID")
        )
        | Q(raw_result__extra__has_key="fix")
        | Q(raw_result__extra__has_key="message")
        | (
            ~Q(raw_result__has_key="VulnerabilityID")
            & (
                _non_empty("check_metadata__Remediation__Recommendation__Text")
                | _non_empty("check_metadata__remediation__recommendation__text")
            )
        )
    )


def app_security_location(raw: dict[str, Any], file: str = "") -> str:
    """Package and version, or file and line, from an imported raw result.

    Misconfiguration and secret results carry only a line; ``file`` is the
    scanned file (the finding's resource) to put in front of it.
    """
    if not isinstance(raw, dict):
        return file
    package = raw.get("PkgName")
    if package:
        version = raw.get("InstalledVersion") or ""
        return f"{package} {version}".strip()
    path = raw.get("path")
    start = raw.get("start")
    if path and isinstance(start, dict) and start.get("line"):
        return f"{path}:{start['line']}"
    cause = raw.get("CauseMetadata")
    line = (cause.get("StartLine") if isinstance(cause, dict) else None) or raw.get(
        "StartLine"
    )
    if line:
        return f"{file}:{line}" if file else f"line {line}"
    return str(path or file)


def _remediation(metadata: dict[str, Any]) -> str:
    remediation = metadata.get("Remediation")
    if not isinstance(remediation, dict):
        return ""
    recommendation = remediation.get("Recommendation")
    if isinstance(recommendation, dict):
        return str(recommendation.get("Text") or "")
    return ""


def _finding_rows(
    tenant_id: str,
    area: str,
    findings: list[dict[str, Any]],
    sources: dict[str, Source],
) -> list[dict[str, Any]]:
    ids = [row["id"] for row in findings]
    resources: dict[str, dict[str, Any]] = {}
    for mapping in (
        ResourceFindingMapping.objects.filter(tenant_id=tenant_id, finding_id__in=ids)
        .order_by("finding_id")
        .values(
            "finding_id",
            "resource__uid",
            "resource__name",
            "resource__type",
            "resource__region",
            "resource__service",
        )
    ):
        resources.setdefault(str(mapping["finding_id"]), mapping)
    triages = _triages_by_uid(tenant_id, [row["uid"] for row in findings])
    rows = []
    for finding in findings:
        metadata = finding["check_metadata"] or {}
        resource = resources.get(str(finding["id"]), {})
        source = sources.get(str(finding["scan_id"]))
        raw = finding["raw_result"] or {}
        snapshot = FindingSnapshot(
            id=str(finding["id"]),
            uid=finding["uid"],
            check_id=finding["check_id"],
            provider_id=source.provider_id if source else None,
            status=finding["status"],
            muted=bool(finding["muted"]),
            inserted_at=finding["inserted_at"],
            area=area,
        )
        categories = metadata.get("Categories") or []
        rows.append(
            {
                "uid": finding["uid"],
                "finding_id": str(finding["id"]),
                "area": area,
                "title": str(metadata.get("CheckTitle") or finding["check_id"]),
                "severity": finding["severity"],
                "status": finding["status"],
                "muted": bool(finding["muted"]),
                "check_id": finding["check_id"],
                "description": str(
                    metadata.get("Description") or finding["status_extended"] or ""
                ),
                "status_extended": finding["status_extended"] or "",
                "remediation": _remediation(metadata),
                **finding_fix(metadata, raw),
                "resource_id": resource.get("resource__uid") or "",
                "resource_name": resource.get("resource__name") or "",
                "resource_type": resource.get("resource__type")
                or next(iter(finding["resource_types"] or []), ""),
                "location": app_security_location(
                    raw, resource.get("resource__name") or ""
                )
                if area == AREA.APPLICATION_SECURITY
                else "",
                "region": resource.get("resource__region")
                or next(iter(finding["resource_regions"] or []), ""),
                "service": resource.get("resource__service")
                or next(iter(finding["resource_services"] or []), ""),
                "source_kind": source.kind if source else "",
                "source_id": source.id if source else "",
                "source_name": source.name if source else "",
                "provider_id": source.provider_id if source else None,
                "scan_id": str(finding["scan_id"]),
                "first_seen_at": finding["first_seen_at"],
                "last_seen_at": finding["inserted_at"],
                "categories": categories if isinstance(categories, list) else [],
                **_triage_fields(triages.get(finding["uid"]), snapshot),
            }
        )
    return rows


_FINDING_FIELDS = (
    "id",
    "uid",
    "check_id",
    "severity",
    "status",
    "status_extended",
    "muted",
    "check_metadata",
    "raw_result",
    "resource_types",
    "resource_regions",
    "resource_services",
    "first_seen_at",
    "inserted_at",
    "scan_id",
)


# --- Governance -------------------------------------------------------------------


def _governance_matches(
    finding: GovernanceFinding,
    query: AreaFindingQuery,
    excluded: set[str],
    kept: set[str] | None,
) -> bool:
    if query.severities and finding.severity not in query.severities:
        return False
    if query.sources and finding.policy_id not in query.sources:
        return False
    if query.search:
        needle = query.search.lower()
        haystack = (
            finding.uid,
            finding.title,
            finding.policy_name,
            finding.resource_id,
            finding.resource_name,
        )
        if not any(needle in value.lower() for value in haystack):
            return False
    if finding.uid in excluded:
        return False
    return kept is None or finding.uid in kept


def _governance_sort_key(query: AreaFindingQuery):
    def key(finding: GovernanceFinding):
        if query.sort == "severity":
            rank = SEVERITY_ORDER.index(finding.severity)
            return (rank, finding.title, finding.resource_id)
        if query.sort == "check_id":
            return (finding.rule_name, finding.resource_id)
        value: datetime | None = getattr(finding, query.sort)
        return (value.timestamp() if value else 0.0, finding.uid)

    return key


def _governance_row(
    finding: GovernanceFinding, triage: FindingTriage | None
) -> dict[str, Any]:
    snapshot = FindingSnapshot(
        id=finding.uid,
        uid=finding.uid,
        check_id=finding.rule_name,
        provider_id=finding.provider_id,
        status=StatusChoices.FAIL,
        muted=False,
        inserted_at=finding.last_seen_at,
        area=AREA.GOVERNANCE,
    )
    return {
        "uid": finding.uid,
        "finding_id": None,
        "area": AREA.GOVERNANCE,
        "title": finding.title,
        "severity": finding.severity,
        "status": StatusChoices.FAIL,
        "muted": False,
        "check_id": finding.rule_name,
        "description": finding.description,
        "status_extended": "",
        "remediation": "",
        **empty_fix(),
        "resource_id": finding.resource_id,
        "resource_name": finding.resource_name,
        "resource_type": finding.resource_type,
        "location": "",
        "region": finding.region,
        "service": finding.resource_type.split(".")[0] if finding.resource_type else "",
        "source_kind": "policy",
        "source_id": finding.policy_id,
        "source_name": finding.policy_name,
        "provider_id": finding.provider_id,
        "run_id": finding.run_id,
        "first_seen_at": finding.first_seen_at,
        "last_seen_at": finding.last_seen_at,
        "categories": [],
        **_triage_fields(triage, snapshot),
    }


def _governance_page(
    tenant_id: str, role: Role, query: AreaFindingQuery
) -> AreaFindingPage:
    findings = governance_findings(tenant_id, role)
    sources = {
        finding.policy_id: Source(
            kind="policy",
            id=finding.policy_id,
            name=finding.policy_name,
            provider_id=finding.provider_id,
        )
        for finding in findings
    }
    excluded: set[str] = set()
    kept: set[str] | None = None
    if query.triage_statuses:
        uids, exclude = _triage_filter_uids(
            tenant_id, query.area, query.triage_statuses
        )
        values = set(uids.values_list("finding_uid", flat=True))
        if exclude:
            excluded = values
        else:
            kept = values
    matches = [
        finding
        for finding in findings
        if _governance_matches(finding, query, excluded, kept)
    ]
    matches.sort(key=_governance_sort_key(query), reverse=query.descending)
    start = (query.page - 1) * query.page_size
    page = matches[start : start + query.page_size]
    triages = _triages_by_uid(tenant_id, [finding.uid for finding in page])
    return AreaFindingPage(
        rows=[_governance_row(finding, triages.get(finding.uid)) for finding in page],
        count=len(matches),
        sources=sorted(sources.values(), key=lambda source: source.name.lower()),
    )


# --- Entry point ---------------------------------------------------------------------


def _unique_sources(sources: dict[str, Source]) -> list[Source]:
    unique = {source.id: source for source in sources.values()}
    return sorted(unique.values(), key=lambda source: (source.name or "").lower())


def list_area_findings(
    tenant_id: str, role: Role, query: AreaFindingQuery
) -> AreaFindingPage:
    """One page of an area's current findings, triage merged in."""
    if query.area == AREA.GOVERNANCE:
        return _governance_page(tenant_id, role, query)
    sources = scan_sources(tenant_id, role, query.area)
    queryset = _finding_queryset(tenant_id, query, sources)
    count = queryset.count()
    start = (query.page - 1) * query.page_size
    findings = list(queryset[start : start + query.page_size].values(*_FINDING_FIELDS))
    return AreaFindingPage(
        rows=_finding_rows(tenant_id, query.area, findings, sources),
        count=count,
        sources=_unique_sources(sources),
    )
