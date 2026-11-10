"""Read scanner records for an assessment report.

Runs inside ``rls_transaction(tenant_id)`` and also filters by ``tenant_id``.

Sources:

* Cloud security: the latest completed cloud scan per provider in the period.
* Application security: the latest completed scan per provider and stream
  (repository, filesystem, image, IaC, SBOM, Kubernetes, code analysis).
* Governance: the latest completed dry run per policy.
* Compliance: requirement results of the cloud scans in scope.

Failed, manual, and unknown results are loaded as records. Passed results are
only counted (per area and severity) because there are usually far more of
them and no report lists them one by one.
"""

from __future__ import annotations

import os
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from api.models import Finding, Provider, ResourceFindingMapping, Scan
from cloudsneeker_api.models import (
    CustodianPolicy,
    CustodianRun,
    FindingTriage,
    TrivyTarget,
)
from cloudsneeker_api.reports.assessment.accuracy import (
    coverage_state,
    normalize_severity,
    normalize_status,
)
from cloudsneeker_api.reports.assessment.model import (
    AREA_APPSEC,
    AREA_CLOUD,
    AREA_GOVERNANCE,
    CATEGORY_CLOUD_CONFIG,
    CATEGORY_CODE,
    CATEGORY_LICENSE,
    CATEGORY_MISCONFIGURATION,
    CATEGORY_POLICY,
    CATEGORY_SECRET,
    CATEGORY_VULNERABILITY,
    STATUS_FAIL,
    AssessmentDataset,
    ComplianceFramework,
    NormalizedFinding,
    SourceCoverage,
    TrendPoint,
)
from cloudsneeker_api.reports.data.common import (
    APPSEC_PROVIDER_TYPES,
    CLOUD_SCOPE,
    ScanScope,
    compliance_posture,
    latest_scan_ids,
    metadata_text,
    scope_scans,
    stream_mode,
)
from cloudsneeker_api.reports.schema import ReportFilters, empty_severity_counts
from cloudsneeker_api.services.area_findings import app_security_location
from cloudsneeker_api.services.finding_fix import finding_fix
from cloudsneeker_api.services.governance_findings import (
    findings_for_run,
    policy_rules,
)
from django.db.models import Count

APPSEC_SCOPE = ScanScope(
    trivy_modes=frozenset({"iac", "image", "fs", "repo", "sbom", "k8s", "sast"}),
    prowler_provider_types=APPSEC_PROVIDER_TYPES,
)
CLOUD_STREAM = "cloud_checks"
CHUNK = 2000
TREND_SCAN_LIMIT = 400


def max_findings() -> int:
    """Bound on records loaded per area (``REPORT_ASSESSMENT_MAX_FINDINGS``)."""
    try:
        return max(100, int(os.environ.get("REPORT_ASSESSMENT_MAX_FINDINGS", "25000")))
    except ValueError:
        return 25000


def _chunks(items: list, size: int = CHUNK) -> Iterable[list]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _value(data: Any, key: str) -> Any:
    if not isinstance(data, dict):
        return None
    if key in data:
        return data[key]
    wanted = key.lower()
    for name, value in data.items():
        if isinstance(name, str) and name.lower() == wanted:
            return value
    return None


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def appsec_category(raw: dict[str, Any], check_id: str, stream: str) -> str:
    """Category of an application security record, from its raw shape."""
    raw = raw if isinstance(raw, dict) else {}
    if "VulnerabilityID" in raw or check_id.upper().startswith(("CVE-", "GHSA-")):
        return CATEGORY_VULNERABILITY
    if "RuleID" in raw and "Match" in raw:
        return CATEGORY_SECRET
    if "Category" in raw and "Name" in raw and "RuleID" not in raw:
        return CATEGORY_LICENSE
    if isinstance(raw.get("extra"), dict) or stream == "sast":
        return CATEGORY_CODE
    return CATEGORY_MISCONFIGURATION


def advisory_values(raw: dict[str, Any]) -> dict[str, Any]:
    """Scores an advisory published, as the scanner stored them.

    Only the NVD (then vendor) CVSS v3 base score and vector are read. Nothing
    is derived or estimated.
    """
    cvss = raw.get("CVSS") if isinstance(raw, dict) else None
    if not isinstance(cvss, dict):
        return {}
    for source in ("nvd", "ghsa", "redhat", *cvss.keys()):
        entry = cvss.get(source)
        if isinstance(entry, dict) and entry.get("V3Score") is not None:
            return {
                "cvss_published": f"{entry['V3Score']} ({source})",
                "cvss_vector": str(entry.get("V3Vector") or ""),
            }
    return {}


def remediation_code(metadata: dict[str, Any]) -> dict[str, str]:
    """``Remediation.Code`` of a check, keyed by lower-case kind."""
    code = _value(_value(metadata, "Remediation"), "Code")
    if not isinstance(code, dict):
        return {}
    return {
        str(key).lower(): str(value)
        for key, value in code.items()
        if isinstance(value, str) and value.strip()
    }


def _references(metadata: dict[str, Any], fix: dict[str, Any]) -> list[str]:
    urls = list(fix.get("fix_references") or [])
    for candidate in (
        _value(metadata, "RelatedUrl"),
        _value(_value(_value(metadata, "Remediation"), "Recommendation"), "Url"),
    ):
        if (
            isinstance(candidate, str)
            and candidate.startswith("http")
            and candidate not in urls
        ):
            urls.append(candidate)
    return urls[:6]


# ---------------------------------------------------------------------------
# Scan-based areas
# ---------------------------------------------------------------------------


def _resources_for(finding_ids: list[UUID]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for chunk in _chunks(finding_ids):
        rows = ResourceFindingMapping.objects.filter(finding_id__in=chunk).values(
            "finding_id",
            "resource__uid",
            "resource__name",
            "resource__region",
            "resource__service",
        )
        for row in rows:
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


def _triage_by_uid(tenant_id: str, uids: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for chunk in _chunks(sorted(set(uids))):
        for uid, status in FindingTriage.objects.filter(
            tenant_id=tenant_id, finding_uid__in=chunk
        ).values_list("finding_uid", "status"):
            result[uid] = status
    return result


def _first(values: list | None) -> str:
    return str(values[0] or "") if values else ""


def normalize_scan_finding(
    row: dict[str, Any], resource: dict[str, str], area: str
) -> NormalizedFinding:
    """Turn one ``Finding`` values row into a ``NormalizedFinding``."""
    metadata = row.get("check_metadata") or {}
    raw = row.get("raw_result") or {}
    provider_type = row.get("scan__provider__provider") or ""
    stream = (
        CLOUD_STREAM
        if area == AREA_CLOUD
        else stream_mode(row.get("scan__scanner_args"), provider_type)
    )
    check_id = str(row.get("check_id") or "")
    category = (
        CATEGORY_CLOUD_CONFIG
        if area == AREA_CLOUD
        else appsec_category(raw, check_id, stream)
    )
    fix = finding_fix(metadata, raw)
    if isinstance(raw, dict):
        purl = _value(raw.get("PkgIdentifier"), "PURL")
        fix = {
            **fix,
            "package": str(raw.get("PkgName") or ""),
            "purl": str(purl or ""),
        }
    resource_uid = resource.get("uid") or ""
    resource_name = resource.get("name") or resource_uid
    location = app_security_location(raw, resource_name) if area == AREA_APPSEC else ""
    return NormalizedFinding(
        source_id=str(row["id"]),
        uid=str(row.get("uid") or ""),
        area=area,
        category=category,
        scanner=stream,
        provider_type=provider_type,
        provider_id=str(row.get("scan__provider_id") or ""),
        provider_label=str(
            row.get("scan__provider__alias") or row.get("scan__provider__uid") or ""
        ),
        account=str(row.get("scan__provider__uid") or ""),
        resource_uid=resource_uid,
        resource_name=resource_name,
        region=resource.get("region") or _first(row.get("resource_regions")),
        service=resource.get("service") or _first(row.get("resource_services")),
        check_id=check_id,
        title=metadata_text(metadata, "CheckTitle", "Title") or check_id,
        severity=normalize_severity(row.get("severity")),
        status=normalize_status(row.get("status")),
        muted=bool(row.get("muted")),
        first_seen_at=row.get("first_seen_at") or row.get("inserted_at"),
        last_seen_at=row.get("scan__completed_at") or row.get("inserted_at"),
        scan_id=str(row.get("scan_id") or ""),
        description=metadata_text(metadata, "Description"),
        risk=metadata_text(metadata, "Risk"),
        status_extended=str(row.get("status_extended") or "")[:1000],
        fix=fix,
        remediation_code=remediation_code(metadata),
        references=_references(metadata, fix),
        advisory=advisory_values(raw),
        compliance=sorted((row.get("compliance") or {}).keys())
        if isinstance(row.get("compliance"), dict)
        else [],
        location=location,
    )


FINDING_FIELDS = (
    "id",
    "uid",
    "check_id",
    "severity",
    "status",
    "status_extended",
    "muted",
    "check_metadata",
    "raw_result",
    "compliance",
    "resource_regions",
    "resource_services",
    "first_seen_at",
    "inserted_at",
    "scan_id",
    "scan__completed_at",
    "scan__provider_id",
    "scan__provider__alias",
    "scan__provider__uid",
    "scan__provider__provider",
    "scan__scanner_args",
)


def load_scan_findings(
    tenant_id: str, scan_ids: list[UUID], area: str, dataset: AssessmentDataset
) -> None:
    """Load non-pass records and pass counts of the given scans into ``dataset``."""
    if not scan_ids:
        return
    base = Finding.all_objects.filter(tenant_id=tenant_id, scan_id__in=scan_ids)
    bound = max_findings()
    rows = list(
        base.exclude(status="PASS").order_by("id").values(*FINDING_FIELDS)[: bound + 1]
    )
    if len(rows) > bound:
        rows = rows[:bound]
        dataset.truncated = True
        dataset.notes.append(
            f"{area}: more than {bound} non-passing records; the first {bound} "
            "were analyzed. Raise REPORT_ASSESSMENT_MAX_FINDINGS to include all."
        )
    resources = _resources_for([row["id"] for row in rows])
    findings = [
        normalize_scan_finding(row, resources.get(str(row["id"]), {}), area)
        for row in rows
    ]
    triage = _triage_by_uid(tenant_id, [item.uid for item in findings])
    for item in findings:
        item.triage_status = triage.get(item.uid, "open")
    dataset.findings.extend(findings)

    passed = dataset.passed.setdefault(area, empty_severity_counts())
    for row in (
        base.filter(status="PASS", muted=False)
        .values("severity")
        .annotate(count=Count("id"))
    ):
        severity = normalize_severity(row["severity"])
        passed[severity] += int(row["count"] or 0)
    dataset.passed_resources[area] = (
        ResourceFindingMapping.objects.filter(
            tenant_id=tenant_id, finding__scan_id__in=scan_ids, finding__status="PASS"
        )
        .values("resource_id")
        .distinct()
        .count()
    )
    failing_uids = base.filter(status="FAIL").values("uid")
    dataset.polarity_conflicts += base.filter(
        status="PASS", uid__in=failing_uids
    ).count()


def scan_coverage(
    tenant_id: str,
    scan_ids: list[UUID],
    area: str,
    expected_providers: list[Provider],
    now: datetime,
    stale_days: int,
) -> list[SourceCoverage]:
    """Coverage rows of the scans in scope plus expected providers with none."""
    rows = Scan.all_objects.filter(tenant_id=tenant_id, id__in=scan_ids).values(
        "id",
        "provider_id",
        "provider__alias",
        "provider__uid",
        "provider__provider",
        "scanner_args",
        "completed_at",
    )
    coverage = []
    covered: set[str] = set()
    for row in rows:
        covered.add(str(row["provider_id"]))
        stream = (
            CLOUD_STREAM
            if area == AREA_CLOUD
            else stream_mode(row["scanner_args"], row["provider__provider"])
        )
        coverage.append(
            SourceCoverage(
                provider_id=str(row["provider_id"]),
                provider_label=str(row["provider__alias"] or row["provider__uid"]),
                provider_type=row["provider__provider"],
                account=str(row["provider__uid"]),
                area=area,
                stream=stream,
                last_assessed_at=row["completed_at"],
                scan_id=str(row["id"]),
                state=coverage_state(row["completed_at"], now, stale_days),
            )
        )
    for provider in expected_providers:
        if str(provider.id) in covered:
            continue
        coverage.append(
            SourceCoverage(
                provider_id=str(provider.id),
                provider_label=str(provider.alias or provider.uid),
                provider_type=provider.provider,
                account=str(provider.uid),
                area=area,
                stream=CLOUD_STREAM if area == AREA_CLOUD else "",
                last_assessed_at=None,
                scan_id="",
                state="not_assessed",
            )
        )
    return sorted(
        coverage, key=lambda item: (item.area, item.provider_label, item.stream)
    )


# ---------------------------------------------------------------------------
# Governance
# ---------------------------------------------------------------------------


def latest_policy_runs(tenant_id: str, filters: ReportFilters) -> list[CustodianRun]:
    """Latest completed run per policy for the providers and period in scope."""
    queryset = CustodianRun.objects.filter(
        tenant_id=tenant_id,
        status=CustodianRun.Status.COMPLETED,
        provider__is_deleted=False,
    )
    if filters.provider_ids:
        queryset = queryset.filter(provider_id__in=filters.provider_ids)
    if filters.date_from:
        queryset = queryset.filter(finished_at__gte=filters.date_from)
    if filters.date_to:
        queryset = queryset.filter(finished_at__lte=filters.date_to)
    return list(
        queryset.select_related("policy", "provider")
        .order_by("policy_id", "-finished_at", "-inserted_at")
        .distinct("policy_id")
    )


def _policy_severity(policy: CustodianPolicy) -> str:
    rules = policy_rules(policy.policy_yaml)
    first = next(iter(rules.values()), None)
    return first.severity if first else "medium"


def load_governance(
    tenant_id: str,
    filters: ReportFilters,
    dataset: AssessmentDataset,
    now: datetime,
    stale_days: int,
) -> None:
    """Load governance findings, pass-equivalent counts, and coverage."""
    runs = latest_policy_runs(tenant_id, filters)
    first_seen: dict[str, datetime] = {}
    if runs:
        for row in (
            CustodianRun.objects.filter(
                tenant_id=tenant_id,
                policy_id__in=[run.policy_id for run in runs],
                status=CustodianRun.Status.COMPLETED,
            )
            .order_by("policy_id", "finished_at")
            .distinct("policy_id")
            .values("policy_id", "finished_at")
        ):
            first_seen[str(row["policy_id"])] = row["finished_at"]
    passed = dataset.passed.setdefault(AREA_GOVERNANCE, empty_severity_counts())
    covered_policies: set[str] = set()
    trimmed = 0
    for run in runs:
        policy = run.policy
        covered_policies.add(str(policy.id))
        provider = run.provider
        items = findings_for_run(run, policy, first_seen.get(str(policy.id)))
        stored = len((run.output or {}).get("resources") or [])
        try:
            reported = int((run.summary or {}).get("resource_count") or stored)
        except (TypeError, ValueError):
            reported = stored
        if reported > stored:
            trimmed += reported - stored
        if not items:
            # A policy that matched nothing is a passed control.
            passed[_policy_severity(policy)] += 1
        for item in items:
            dataset.findings.append(
                NormalizedFinding(
                    source_id=item.uid,
                    uid=item.uid,
                    area=AREA_GOVERNANCE,
                    category=CATEGORY_POLICY,
                    scanner="governance",
                    provider_type=provider.provider,
                    provider_id=str(provider.id),
                    provider_label=str(provider.alias or provider.uid),
                    account=str(provider.uid),
                    resource_uid=item.resource_id,
                    resource_name=item.resource_name,
                    region=item.region,
                    service=item.resource_type,
                    check_id=item.rule_name,
                    title=item.title,
                    severity=normalize_severity(item.severity),
                    status=STATUS_FAIL,
                    first_seen_at=item.first_seen_at,
                    last_seen_at=item.last_seen_at,
                    scan_id=str(run.id),
                    description=item.description,
                    status_extended=f"Matched by policy {policy.name}.",
                    fix={"fix_available": False, "fix_summary": ""},
                )
            )
        dataset.coverage.append(
            SourceCoverage(
                provider_id=str(provider.id),
                provider_label=str(provider.alias or provider.uid),
                provider_type=provider.provider,
                account=str(provider.uid),
                area=AREA_GOVERNANCE,
                stream=policy.name,
                last_assessed_at=run.finished_at,
                scan_id=str(run.id),
                state=coverage_state(run.finished_at, now, stale_days),
            )
        )
    if trimmed:
        dataset.notes.append(
            f"governance: {trimmed} matched resource(s) were trimmed from stored "
            "run output and are counted in run summaries only."
        )
    policies = CustodianPolicy.objects.filter(tenant_id=tenant_id).select_related(
        "provider"
    )
    if filters.provider_ids:
        policies = policies.filter(provider_id__in=filters.provider_ids)
    for policy in policies.filter(provider__is_deleted=False):
        if str(policy.id) in covered_policies:
            continue
        provider = policy.provider
        dataset.coverage.append(
            SourceCoverage(
                provider_id=str(provider.id),
                provider_label=str(provider.alias or provider.uid),
                provider_type=provider.provider,
                account=str(provider.uid),
                area=AREA_GOVERNANCE,
                stream=policy.name,
                last_assessed_at=None,
                scan_id="",
                state="not_assessed",
            )
        )


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------


def load_compliance(
    tenant_id: str,
    cloud_scan_ids: list[UUID],
    provider_types: set[str],
    selected: list[str],
) -> list[ComplianceFramework]:
    """Assessed, enabled, and available frameworks for the scope.

    * assessed: requirement results exist in the cloud scans in scope;
    * enabled: chosen for the report but without results in scope;
    * available: offered for a provider type in scope, not evaluated here.
    """
    from api.compliance import get_compliance_frameworks

    posture = {
        row["compliance_id"]: row
        for row in compliance_posture(tenant_id, cloud_scan_ids)
    }
    available: dict[str, set[str]] = defaultdict(set)
    for provider_type in sorted(provider_types):
        try:
            frameworks = get_compliance_frameworks(provider_type)
        except Exception:  # noqa: BLE001 - unknown provider types offer none
            frameworks = []
        for framework in frameworks:
            available[framework].add(provider_type)
    result: list[ComplianceFramework] = []
    for framework_id, row in posture.items():
        if selected and framework_id not in selected:
            continue
        result.append(
            ComplianceFramework(
                framework_id=framework_id,
                provider_types=sorted(available.get(framework_id, set())),
                state="assessed",
                passed=int(row["passed"]),
                failed=int(row["failed"]),
                manual=int(row["manual"]),
                total=int(row["total"]),
            )
        )
    for framework_id in selected:
        if framework_id not in posture:
            result.append(
                ComplianceFramework(
                    framework_id=framework_id,
                    provider_types=sorted(available.get(framework_id, set())),
                    state="enabled",
                )
            )
    for framework_id, types in sorted(available.items()):
        if framework_id in posture or framework_id in selected:
            continue
        result.append(
            ComplianceFramework(
                framework_id=framework_id,
                provider_types=sorted(types),
                state="available",
            )
        )
    return result


# ---------------------------------------------------------------------------
# Trend
# ---------------------------------------------------------------------------


def trend_dates(start: datetime, end: datetime) -> list[datetime]:
    """Sample moments between ``start`` and ``end`` (8 to 14 points)."""
    days = max(1, (end - start).days)
    step = (
        1 if days <= 8 else 3 if days <= 31 else 7 if days <= 92 else max(1, days // 12)
    )
    moments = []
    moment = end
    while moment >= start and len(moments) < 31:
        moments.append(moment)
        moment -= timedelta(days=step)
    return sorted(moments)


def load_trend(
    tenant_id: str,
    filters: ReportFilters,
    scopes: list[tuple[str, ScanScope]],
    start: datetime,
    end: datetime,
) -> list[TrendPoint]:
    """Coverage-aware exposure trend for scan-based areas.

    For every sample moment the latest scan per source completed by then is
    used. A point is comparable only when it covers the same sources as the
    end of the period, so a drop caused by a source missing from the window
    is never shown as an improvement.
    """
    window = ReportFilters(provider_ids=filters.provider_ids, date_to=end)
    scans: list[tuple[str, str, datetime]] = []
    for area, scope in scopes:
        rows = (
            scope_scans(tenant_id, window, scope)
            .exclude(completed_at__isnull=True)
            .filter(completed_at__gte=start - timedelta(days=90))
            .order_by("-completed_at")
            .values_list(
                "id",
                "provider_id",
                "provider__provider",
                "scanner_args",
                "completed_at",
            )[:TREND_SCAN_LIMIT]
        )
        for scan_id, provider_id, provider_type, scanner_args, completed_at in rows:
            stream = (
                CLOUD_STREAM
                if area == AREA_CLOUD
                else stream_mode(scanner_args, provider_type)
            )
            scans.append((str(scan_id), f"{area}|{provider_id}|{stream}", completed_at))
    if not scans:
        return []
    counts: dict[str, dict[str, int]] = defaultdict(empty_severity_counts)
    ids = [scan_id for scan_id, _, _ in scans]
    for chunk in _chunks(ids, 500):
        for row in (
            Finding.all_objects.filter(
                tenant_id=tenant_id, scan_id__in=chunk, status="FAIL", muted=False
            )
            .values("scan_id", "severity")
            .annotate(count=Count("id"))
        ):
            counts[str(row["scan_id"])][normalize_severity(row["severity"])] += int(
                row["count"]
            )
    points: list[TrendPoint] = []
    snapshots = []
    for moment in trend_dates(start, end):
        latest: dict[str, tuple[datetime, str]] = {}
        for scan_id, stream, completed_at in scans:
            if completed_at > moment:
                continue
            current = latest.get(stream)
            if current is None or completed_at > current[0]:
                latest[stream] = (completed_at, scan_id)
        snapshots.append((moment, latest))
    final_streams = set(snapshots[-1][1]) if snapshots else set()
    for moment, latest in snapshots:
        totals = empty_severity_counts()
        for _, scan_id in latest.values():
            for severity, value in counts.get(scan_id, {}).items():
                totals[severity] += value
        points.append(
            TrendPoint(
                date=moment.date().isoformat(),
                open_by_severity=totals,
                sources=len(latest),
                comparable=set(latest) == final_streams,
            )
        )
    return points


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def collect(
    tenant_id: str,
    filters: ReportFilters,
    areas: set[str],
    *,
    now: datetime,
    stale_days: int,
    frameworks: list[str] | None = None,
    include_compliance: bool = False,
    trend_start: datetime | None = None,
) -> AssessmentDataset:
    """Collect everything one assessment report needs.

    Args:
        tenant_id: Tenant UUID string.
        filters: Providers and the assessment period.
        areas: Areas the report covers.
        now: Report time.
        stale_days: Age at which a source counts as stale.
        frameworks: Frameworks chosen for the report (empty means all assessed).
        include_compliance: Load compliance framework posture.
        trend_start: Start of the trend window (defaults to 30 days before now).

    Returns:
        ``AssessmentDataset``.
    """
    dataset = AssessmentDataset()
    providers = list(
        Provider.objects.filter(tenant_id=tenant_id, is_deleted=False).order_by(
            "provider", "alias"
        )
    )
    if filters.provider_ids:
        providers = [
            item for item in providers if str(item.id) in set(filters.provider_ids)
        ]
    cloud_providers = [
        item for item in providers if item.provider not in APPSEC_PROVIDER_TYPES
    ]

    cloud_ids: list[UUID] = []
    trend_scopes: list[tuple[str, ScanScope]] = []
    if AREA_CLOUD in areas or include_compliance:
        cloud_ids = list(latest_scan_ids(tenant_id, filters, CLOUD_SCOPE))
    if AREA_CLOUD in areas:
        load_scan_findings(tenant_id, cloud_ids, AREA_CLOUD, dataset)
        dataset.coverage.extend(
            scan_coverage(
                tenant_id, cloud_ids, AREA_CLOUD, cloud_providers, now, stale_days
            )
        )
        trend_scopes.append((AREA_CLOUD, CLOUD_SCOPE))
    if AREA_APPSEC in areas:
        app_ids = list(latest_scan_ids(tenant_id, filters, APPSEC_SCOPE))
        load_scan_findings(tenant_id, app_ids, AREA_APPSEC, dataset)
        target_providers = {
            str(provider_id)
            for provider_id in TrivyTarget.objects.filter(
                tenant_id=tenant_id
            ).values_list("provider_id", flat=True)
        }
        expected = [
            item
            for item in providers
            if item.provider in APPSEC_PROVIDER_TYPES
            or str(item.id) in target_providers
        ]
        dataset.coverage.extend(
            scan_coverage(tenant_id, app_ids, AREA_APPSEC, expected, now, stale_days)
        )
        trend_scopes.append((AREA_APPSEC, APPSEC_SCOPE))
    if AREA_GOVERNANCE in areas:
        load_governance(tenant_id, filters, dataset, now, stale_days)
    if include_compliance:
        dataset.compliance = load_compliance(
            tenant_id,
            cloud_ids,
            {item.provider for item in cloud_providers},
            list(frameworks or []),
        )
    if trend_scopes:
        end = filters.date_to or now
        start = trend_start or filters.date_from or (end - timedelta(days=30))
        dataset.trend = load_trend(tenant_id, filters, trend_scopes, start, end)
    return dataset
