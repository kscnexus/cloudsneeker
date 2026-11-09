"""Assemble the content of one assessment report.

``build_content`` is pure: it takes an ``AssessmentDataset`` and returns the
report content (a JSON-safe mapping). ``assemble`` wires it to the database
and the run pipeline and fills the shared ``ReportData`` fields so the in-app
report page shows the same numbers as the PDF.
"""

from __future__ import annotations

import os
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from cloudsneeker_api.reports.assessment import ENGINE_VERSION
from cloudsneeker_api.reports.assessment.accuracy import (
    DEFAULT_STALE_DAYS,
    compute_totals,
    coverage_warnings,
    dedupe,
    reconcile,
    validate_polarity,
)
from cloudsneeker_api.reports.assessment.model import (
    AREA_APPSEC,
    AREA_CLOUD,
    AREA_GOVERNANCE,
    AREA_LABELS,
    CATEGORY_LABELS,
    NOT_ASSESSED,
    AssessmentDataset,
    NormalizedFinding,
)
from cloudsneeker_api.reports.assessment.recommend import clean_text, priority_for
from cloudsneeker_api.reports.assessment.roadmap import (
    assign_refs,
    group_row,
    issue_groups,
    roadmap,
    top_risks,
)
from cloudsneeker_api.reports.assessment.scoring import (
    area_scores,
    area_summary,
    grade_for,
    kpis,
    overall_score,
    severity_rank,
)
from cloudsneeker_api.reports.schema import (
    SEVERITY_ORDER,
    ReportData,
    ReportFilters,
    ReportTable,
)

SECURITY_ASSESSMENT = "security_assessment"
APPSEC_ASSESSMENT = "appsec_assessment"
CLOUD_ASSESSMENT = "cloud_assessment"
GOVERNANCE_ASSESSMENT = "governance_assessment"


@dataclass(frozen=True)
class AssessmentSpec:
    """What one assessment report type covers."""

    report_type: str
    title: str
    areas: frozenset[str]
    compliance: bool
    executive: bool


SPECS: dict[str, AssessmentSpec] = {
    SECURITY_ASSESSMENT: AssessmentSpec(
        SECURITY_ASSESSMENT,
        "Executive Security Assessment",
        frozenset({AREA_CLOUD, AREA_APPSEC, AREA_GOVERNANCE}),
        compliance=True,
        executive=True,
    ),
    APPSEC_ASSESSMENT: AssessmentSpec(
        APPSEC_ASSESSMENT,
        "Application Security Assessment",
        frozenset({AREA_APPSEC}),
        compliance=False,
        executive=False,
    ),
    CLOUD_ASSESSMENT: AssessmentSpec(
        CLOUD_ASSESSMENT,
        "Cloud Security Assessment",
        frozenset({AREA_CLOUD}),
        compliance=False,
        executive=False,
    ),
    GOVERNANCE_ASSESSMENT: AssessmentSpec(
        GOVERNANCE_ASSESSMENT,
        "Governance and Compliance Assessment",
        frozenset({AREA_GOVERNANCE}),
        compliance=True,
        executive=False,
    ),
}

# Optional sections; cover, scope, summary, methodology, and quality always print.
SECTION_TREND = "trend"
SECTION_TOP_RISKS = "top_risks"
SECTION_POSTURE = "posture"
SECTION_COMPLIANCE = "compliance"
SECTION_ROADMAP = "roadmap"
SECTION_APPENDIX = "appendix"
SECTION_AI = "ai_insights"
OPTIONAL_SECTIONS: tuple[str, ...] = (
    SECTION_TREND,
    SECTION_TOP_RISKS,
    SECTION_POSTURE,
    SECTION_COMPLIANCE,
    SECTION_ROADMAP,
    SECTION_APPENDIX,
    SECTION_AI,
)
DEFAULT_SECTIONS: tuple[str, ...] = tuple(
    s for s in OPTIONAL_SECTIONS if s != SECTION_AI
)

PERIODS: dict[str, int | None] = {
    "7d": 7,
    "30d": 30,
    "90d": 90,
    "latest": None,
    "custom": None,
}

COMPLIANCE_DISCLAIMER = (
    "Framework results are automated checks of technical controls mapped to the "
    "framework. They are not an audit, certification, or attestation, and "
    "requirements that need a manual check are not counted as passed."
)

APPENDIX_COLUMNS: list[tuple[str, str]] = [
    ("ref", "Ref"),
    ("severity", "Severity"),
    ("title", "Finding"),
    ("check_id", "Check / rule"),
    ("resource", "Resource"),
    ("account", "Account / target"),
    ("region", "Region"),
    ("priority", "Priority"),
    ("triage_status", "Triage"),
    ("first_seen", "First seen"),
    ("fix", "Fix"),
]


def period_window(
    period: str | None,
    now: datetime,
    date_from: datetime | None,
    date_to: datetime | None,
) -> tuple[datetime | None, datetime | None, str]:
    """Return ``(from, to, label)`` for a period choice.

    ``latest`` reads the latest result of every source whatever its age (the
    coverage table then flags stale ones); ``custom`` uses the given dates.
    """
    days = PERIODS.get(period or "latest")
    if days:
        return now - timedelta(days=days), now, f"Last {days} days"
    if period == "custom" and (date_from or date_to):
        start = date_from.date().isoformat() if date_from else "start"
        end = date_to.date().isoformat() if date_to else "now"
        return date_from, date_to, f"{start} to {end}"
    return None, None, "Latest results"


def finding_row(finding: NormalizedFinding) -> dict[str, Any]:
    """Appendix row of one finding."""
    fix = finding.fix or {}
    fixed = fix.get("fixed_version")
    return {
        "ref": finding.ref,
        "severity": finding.severity,
        "title": clean_text(finding.title, limit=200) or finding.check_id,
        "check_id": finding.check_id,
        "resource": clean_text(
            finding.location or finding.resource_name or finding.resource_uid, 200
        ),
        "account": finding.provider_label,
        "region": finding.region or "-",
        "priority": priority_for(finding) or "-",
        "triage_status": finding.triage_status.replace("_", " "),
        "first_seen": finding.first_seen_at.date().isoformat()
        if finding.first_seen_at
        else "-",
        "fix": f"Upgrade to {fixed}"
        if fixed
        else ("Yes" if fix.get("fix_available") else "None recorded"),
    }


def appendix_row_limit() -> int:
    """Rows printed in the appendix (``REPORT_ASSESSMENT_APPENDIX_ROWS``)."""
    try:
        return max(50, int(os.environ.get("REPORT_ASSESSMENT_APPENDIX_ROWS", "1500")))
    except ValueError:
        return 1500


def appendix(
    findings: list[NormalizedFinding], limit: int | None = None
) -> dict[str, Any]:
    """Open findings grouped by category, then severity.

    Rows are bounded (most severe first); the CSV export carries every row.
    """
    budget = limit or appendix_row_limit()
    by_category: dict[str, dict[str, list[NormalizedFinding]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for finding in findings:
        if finding.is_open:
            by_category[finding.category][finding.severity].append(finding)
    categories = sorted(by_category, key=lambda c: CATEGORY_LABELS.get(c, c))
    # Spend the row budget by severity first, so critical rows of every
    # category print before any low row.
    shown: dict[tuple[str, str], int] = {}
    for severity in SEVERITY_ORDER:
        for category in categories:
            count = len(by_category[category].get(severity, []))
            take = min(count, max(0, budget))
            shown[(category, severity)] = take
            budget -= take
    groups = []
    for category in categories:
        severities = []
        for severity in SEVERITY_ORDER:
            items = sorted(by_category[category].get(severity, []), key=lambda f: f.ref)
            if items:
                severities.append(
                    {
                        "severity": severity,
                        "count": len(items),
                        "rows": [
                            finding_row(f) for f in items[: shown[(category, severity)]]
                        ],
                    }
                )
        groups.append(
            {
                "category": category,
                "label": CATEGORY_LABELS.get(category, category),
                "count": sum(item["count"] for item in severities),
                "severities": severities,
            }
        )
    total = sum(group["count"] for group in groups)
    printed = sum(len(sev["rows"]) for group in groups for sev in group["severities"])
    return {
        "groups": groups,
        "total": total,
        "printed": printed,
        "truncated": printed < total,
    }


def _trend_section(dataset: AssessmentDataset) -> dict[str, Any]:
    points = [
        {
            "date": point.date,
            **point.open_by_severity,
            "total": sum(point.open_by_severity.values()),
            "sources": point.sources,
            "comparable": point.comparable,
        }
        for point in dataset.trend
    ]
    comparable = [point for point in points if point["comparable"]]
    notes = [
        "Trend points count open findings per scan, before cross-source "
        "deduplication, so they can differ slightly from the headline totals."
    ]
    if len(points) > len(comparable):
        notes.append(
            f"{len(points) - len(comparable)} of {len(points)} point(s) covered a "
            "different set of sources than the end of the period. They are marked "
            "and excluded from the change figure."
        )
    change = None
    if len(comparable) >= 2:
        first, last = comparable[0], comparable[-1]
        change = {
            "from_date": first["date"],
            "to_date": last["date"],
            "critical_high_from": first["critical"] + first["high"],
            "critical_high_to": last["critical"] + last["high"],
            "total_from": first["total"],
            "total_to": last["total"],
        }
    return {"points": points, "change": change, "notes": notes}


def _coverage_rows(dataset: AssessmentDataset) -> list[dict[str, Any]]:
    return [
        {
            "area": AREA_LABELS.get(row.area, row.area),
            "source": row.provider_label,
            "type": row.provider_type,
            "stream": row.stream or "-",
            "last_assessed": row.last_assessed_at.isoformat()
            if row.last_assessed_at
            else NOT_ASSESSED,
            "state": {
                "current": "Current",
                "stale": "Stale",
                "not_assessed": NOT_ASSESSED,
            }[row.state],
        }
        for row in dataset.coverage
    ]


def _compliance_section(dataset: AssessmentDataset) -> dict[str, Any]:
    assessed = [item for item in dataset.compliance if item.state == "assessed"]
    enabled = [item for item in dataset.compliance if item.state == "enabled"]
    available = [item for item in dataset.compliance if item.state == "available"]
    rows = sorted(
        (
            {
                "framework": item.framework_id,
                "passed": item.passed,
                "failed": item.failed,
                "manual": item.manual,
                "total": item.total,
                "pass_pct": item.pass_pct,
            }
            for item in assessed
        ),
        key=lambda row: (
            row["pass_pct"] if row["pass_pct"] is not None else 101,
            row["framework"],
        ),
    )
    return {
        "assessed": rows,
        "enabled_not_assessed": [item.framework_id for item in enabled],
        "available_count": len(available),
        "available": [item.framework_id for item in available][:60],
        "disclaimer": COMPLIANCE_DISCLAIMER,
    }


def _distribution(findings: list[NormalizedFinding]) -> dict[str, Any]:
    by_area: Counter[str] = Counter()
    by_category: Counter[str] = Counter()
    by_provider: Counter[str] = Counter()
    for finding in findings:
        if not finding.is_open:
            continue
        by_area[AREA_LABELS.get(finding.area, finding.area)] += 1
        by_category[CATEGORY_LABELS.get(finding.category, finding.category)] += 1
        by_provider[finding.provider_label or finding.provider_type] += 1
    return {
        "by_area": dict(by_area.most_common()),
        "by_category": dict(by_category.most_common()),
        "by_provider": dict(by_provider.most_common(12)),
    }


def narrative(
    *,
    spec: AssessmentSpec,
    score: float | None,
    grade: str,
    area_rows: list[dict[str, Any]],
    metrics: dict[str, Any],
    risks: list[dict[str, Any]],
    trend: dict[str, Any] | None,
    warnings: list[str],
) -> list[dict[str, Any]]:
    """Evidence-based summary statements, each with its sources."""
    statements: list[dict[str, Any]] = []
    assessed = [row["label"] for row in area_rows if row["assessed"]]
    missing = [row["label"] for row in area_rows if not row["assessed"]]
    if score is None:
        statements.append(
            {
                "text": "No source in scope has a completed assessment for this period, "
                "so no score is given. Results below are marked not assessed.",
                "metrics": ["sources_assessed"],
                "refs": [],
            }
        )
        return statements
    text = f"The security score is {score:.0f}/100 (grade {grade}), based on {', '.join(assessed)}."
    if missing:
        text += f" {', '.join(missing)} {'was' if len(missing) == 1 else 'were'} not assessed and is not part of the score."
    statements.append({"text": text, "metrics": ["overall_score", "grade"], "refs": []})
    statements.append(
        {
            "text": (
                f"There are {metrics['open_findings']} open finding(s) on "
                f"{metrics['affected_resources']} unique resource(s): "
                f"{metrics['critical']} critical and {metrics['high']} high."
            ),
            "metrics": ["open_findings", "affected_resources", "critical", "high"],
            "refs": [],
        }
    )
    if risks:
        lead = risks[0]
        statements.append(
            {
                "text": (
                    f'The highest-priority issue is "{lead["title"]}" ({lead["priority"]}, '
                    f"{lead['severity']}), on {lead['resources']} resource(s). "
                    f"{lead['justification']}"
                ),
                "metrics": [],
                "refs": [lead["lead_ref"]],
            }
        )
    if metrics.get("fix_available_pct") is not None:
        statements.append(
            {
                "text": f"{metrics['fix_available_pct']:.0f}% of open findings have a fixed version or a documented fix.",
                "metrics": ["fix_available_pct"],
                "refs": [],
            }
        )
    change = (trend or {}).get("change")
    if change:
        statements.append(
            {
                "text": (
                    f"On a like-for-like set of sources, open critical and high findings went "
                    f"from {change['critical_high_from']} ({change['from_date']}) to "
                    f"{change['critical_high_to']} ({change['to_date']})."
                ),
                "metrics": ["trend"],
                "refs": [],
            }
        )
    elif trend is not None and trend.get("points"):
        statements.append(
            {
                "text": "The set of assessed sources changed during the period, so no like-for-like trend is stated.",
                "metrics": ["trend"],
                "refs": [],
            }
        )
    for warning in warnings:
        statements.append({"text": warning, "metrics": ["coverage"], "refs": []})
    return statements


def methodology(spec: AssessmentSpec, stale_days: int) -> list[str]:
    """How the numbers were produced."""
    items = [
        "Exposure is decided by the scanner's result status: only failed results "
        "are findings. Passed results count as working controls; results that "
        "need a manual check and unrecognized statuses are not assessed.",
        "Muted findings are excluded from open counts and listed separately.",
        "Records with the same provider, account, resource, check, scanner, and "
        "status are merged; the export lists every merged source record.",
        "Findings and unique affected resources are counted separately.",
        "Scores use severity weights (critical 10, high 5, medium 2, low 0.5). "
        "With passed results the score is the weighted pass share; with failures "
        "only it decreases as weighted open findings grow. Areas without an "
        "assessed source get no score instead of zero.",
        f"A source is stale when its latest result is older than {stale_days} days.",
        "Priorities follow fixed rules on scanner severity, exposed credentials, "
        "and fix availability. No CVSS, EPSS, exploit, or asset-criticality value "
        "is estimated; advisory scores are shown only when the scanner recorded them.",
        "Suggested owners, SLAs, and target dates are proposals to adapt to your "
        "organization.",
    ]
    if spec.compliance:
        items.append(COMPLIANCE_DISCLAIMER)
    return items


def build_content(
    *,
    spec: AssessmentSpec,
    dataset: AssessmentDataset,
    now: datetime,
    period_label: str,
    period_from: datetime | None,
    period_to: datetime | None,
    sections: list[str],
    scope: dict[str, Any],
    stale_days: int = DEFAULT_STALE_DAYS,
) -> tuple[dict[str, Any], list[NormalizedFinding]]:
    """Compute the report content from collected data.

    Args:
        spec: Report type.
        dataset: Collected data.
        now: Report time.
        period_label: Readable period.
        period_from: Period start.
        period_to: Period end.
        sections: Optional sections to include.
        scope: Scope description (providers, frameworks...).
        stale_days: Stale threshold.

    Returns:
        ``(content, unique findings)``.
    """
    result = dedupe(item for item in dataset.findings if item.area in spec.areas)
    findings = result.findings
    assign_refs(findings)
    polarity = validate_polarity(findings, db_conflicts=dataset.polarity_conflicts)
    passed = {
        area: counts for area, counts in dataset.passed.items() if area in spec.areas
    }
    totals = compute_totals(findings, passed)
    checks = reconcile(totals)
    coverage = [row for row in dataset.coverage if row.area in spec.areas]
    assessed_areas = {row.area for row in coverage if row.state != "not_assessed"}
    scores = {
        area: score
        for area, score in area_scores(findings, passed, assessed_areas).items()
        if area in spec.areas
    }
    score = overall_score(scores)
    grade = grade_for(score)
    groups = issue_groups(findings, now=now)
    warnings = coverage_warnings(coverage, stale_days) + list(dataset.notes)
    frameworks_assessed = sum(
        1 for item in dataset.compliance if item.state == "assessed"
    )
    metrics = kpis(
        findings,
        totals,
        now=now,
        sources_assessed=sum(1 for row in coverage if row.state != "not_assessed"),
        sources_in_scope=len(coverage),
        frameworks_assessed=frameworks_assessed,
    )
    metrics["overall_score"] = score
    metrics["grade"] = grade
    metrics["duplicates_merged"] = result.removed

    area_rows = []
    for area in (AREA_CLOUD, AREA_APPSEC, AREA_GOVERNANCE):
        if area not in spec.areas:
            continue
        area_findings = [item for item in findings if item.area == area]
        area_rows.append(
            area_summary(
                area,
                scores.get(area),
                compute_totals(area_findings, {area: passed.get(area, {})}),
                area in assessed_areas,
            )
        )

    risks = top_risks(groups, limit=10)
    trend = _trend_section(dataset) if SECTION_TREND in sections else None

    posture: dict[str, Any] = {}
    if SECTION_POSTURE in sections:
        for row in area_rows:
            area = row["area"]
            area_groups = [group for group in groups if group.lead.area == area]
            area_findings = [
                item for item in findings if item.area == area and item.is_open
            ]
            by_category = Counter(
                CATEGORY_LABELS.get(item.category, item.category)
                for item in area_findings
            )
            by_severity = Counter(item.severity for item in area_findings)
            by_account = Counter(item.provider_label for item in area_findings)
            posture[area] = {
                **row,
                "by_severity": {sev: by_severity.get(sev, 0) for sev in SEVERITY_ORDER},
                "by_category": dict(by_category.most_common()),
                "by_account": dict(by_account.most_common(10)),
                "top_issues": [group_row(group) for group in area_groups[:8]],
                "passed_results": sum((passed.get(area) or {}).values()),
                "passed_resources": dataset.passed_resources.get(area),
            }

    content: dict[str, Any] = {
        "meta": {
            "report_type": spec.report_type,
            "title": spec.title,
            "engine_version": ENGINE_VERSION,
            "generated_at": now.isoformat(),
            "period": {
                "label": period_label,
                "from": period_from.isoformat() if period_from else None,
                "to": period_to.isoformat() if period_to else None,
            },
            "scope": scope,
            "areas": [
                AREA_LABELS[area]
                for area in (AREA_CLOUD, AREA_APPSEC, AREA_GOVERNANCE)
                if area in spec.areas
            ],
            "sections": list(sections),
            "classification": "Confidential",
        },
        "coverage": {
            "rows": _coverage_rows(_filtered(dataset, spec)),
            "warnings": warnings,
        },
        "summary": {
            "score": score,
            "grade": grade,
            "kpis": metrics,
            "areas": area_rows,
            "narrative": narrative(
                spec=spec,
                score=score,
                grade=grade,
                area_rows=area_rows,
                metrics=metrics,
                risks=risks,
                trend=trend,
                warnings=coverage_warnings(coverage, stale_days),
            ),
        },
        "distribution": {
            "by_severity": dict(totals.open_by_severity),
            **_distribution(findings),
        },
        "trend": trend,
        "top_risks": risks if SECTION_TOP_RISKS in sections else None,
        "posture": posture or None,
        "compliance": _compliance_section(dataset)
        if spec.compliance and SECTION_COMPLIANCE in sections
        else None,
        "roadmap": roadmap(groups) if SECTION_ROADMAP in sections else None,
        "appendix": appendix(findings) if SECTION_APPENDIX in sections else None,
        "ai": None,
        "accuracy": {
            "input_records": result.input_count,
            "duplicates_merged": result.removed,
            "duplicate_groups": result.groups,
            "polarity": {
                "unknown_status": polarity.unknown_status,
                "manual": polarity.manual,
                "conflicts": polarity.conflicts,
                "informational_open": polarity.informational_open,
                "issues": polarity.issues,
            },
            "reconciliation": [
                {"rule": check.rule, "ok": check.ok, "detail": check.detail}
                for check in checks
            ],
            "truncated": dataset.truncated,
            "muted": totals.muted,
        },
        "methodology": methodology(spec, stale_days),
        "quality": None,
    }
    return content, findings


def _filtered(dataset: AssessmentDataset, spec: AssessmentSpec) -> AssessmentDataset:
    return AssessmentDataset(
        coverage=[row for row in dataset.coverage if row.area in spec.areas]
    )


def legacy_fields(
    data: ReportData, content: dict[str, Any], findings: list[NormalizedFinding]
) -> None:
    """Fill the shared ``ReportData`` fields the in-app report page reads."""
    summary = content["summary"]
    metrics = summary["kpis"]
    data.score = summary["score"]
    data.grade = summary["grade"]
    data.headline = " ".join(item["text"] for item in summary["narrative"][:2])
    data.kpis = {
        key: metrics[key]
        for key in (
            "open_findings",
            "affected_resources",
            "critical",
            "high",
            "fix_available_pct",
            "sources_assessed",
            "frameworks_assessed",
        )
        if key in metrics
    }
    data.severity_totals = {
        sev: content["distribution"]["by_severity"].get(sev, 0)
        for sev in SEVERITY_ORDER
    }
    data.status_totals = {
        "pass": metrics["passed_results"],
        "fail": metrics["open_findings"],
        "muted": metrics["muted"],
        "manual": metrics["manual_review"],
    }
    data.top_risks = [
        {
            "check_id": risk["check_id"],
            "title": risk["title"],
            "severity": risk["severity"],
            "findings": risk["findings"],
            "resources": risk["resources"],
            "impact": risk["recommendation"]["business_impact"]["potential"],
            "remediation": " ".join(risk["recommendation"]["instructions"][:2]),
        }
        for risk in content.get("top_risks") or []
    ]
    data.trend = [
        {
            "date": point["date"],
            "fail": point["total"],
            "pass": 0,
            "critical": point["critical"],
            "high": point["high"],
        }
        for point in (content.get("trend") or {}).get("points", [])
    ]
    if content.get("compliance"):
        data.compliance = [
            {
                "compliance_id": row["framework"],
                **{
                    k: row[k]
                    for k in ("passed", "failed", "manual", "total", "pass_pct")
                },
            }
            for row in content["compliance"]["assessed"]
        ]
    actions = []
    for window in content.get("roadmap") or []:
        for item in window["items"][:3]:
            actions.append(
                {
                    "priority": len(actions) + 1,
                    "action": f"[{item['priority']}, {window['label']}] {item['title']}",
                    "why": item["justification"],
                }
            )
    data.remediation = actions[:10]
    rows = sorted(
        (finding_row(item) for item in findings if item.is_open),
        key=lambda row: (severity_rank(row["severity"]), row["ref"]),
    )
    data.tables = [
        ReportTable(
            key="findings",
            title="Open findings",
            columns=APPENDIX_COLUMNS,
            rows=rows,
            total=len(rows),
        )
    ]
    if not findings and metrics["sources_assessed"] == 0:
        data.empty_state = summary["narrative"][0]["text"]


def assemble_for(
    report_type: str, tenant_id: str, filters: ReportFilters
) -> ReportData:
    """Assemble one assessment report (the run pipeline entry point)."""
    from cloudsneeker_api.reports.assessment.collect import collect
    from django.utils import timezone

    spec = SPECS[report_type]
    now = timezone.now()
    options = dict(filters.options or {})
    sections = [
        s
        for s in (options.get("sections") or DEFAULT_SECTIONS)
        if s in OPTIONAL_SECTIONS
    ]
    stale_days = int(options.get("stale_days") or DEFAULT_STALE_DAYS)
    start, end, label = period_window(
        options.get("period"), now, filters.date_from, filters.date_to
    )
    window = ReportFilters(
        provider_ids=filters.provider_ids, date_from=start, date_to=end
    )
    frameworks = list(options.get("frameworks") or [])
    dataset = collect(
        tenant_id,
        window,
        set(spec.areas),
        now=now,
        stale_days=stale_days,
        frameworks=frameworks,
        include_compliance=spec.compliance,
        trend_start=start or now - timedelta(days=30),
    )
    scope = {
        "provider_ids": list(filters.provider_ids),
        "providers": sorted({row.provider_label for row in dataset.coverage}),
        "frameworks": frameworks,
        "stale_days": stale_days,
    }
    content, findings = build_content(
        spec=spec,
        dataset=dataset,
        now=now,
        period_label=label,
        period_from=start,
        period_to=end,
        sections=sections,
        scope=scope,
        stale_days=stale_days,
    )
    if SECTION_AI in sections:
        from cloudsneeker_api.reports.assessment.ai import ai_insights

        content["ai"] = ai_insights(tenant_id, content)
    data = ReportData(
        report_type=report_type, title=spec.title, generated_at=now, filters=filters
    )
    legacy_fields(data, content, findings)
    data.extra["assessment"] = content
    # Not a dataclass field: renderers read it, the JSON payload does not carry it.
    data.assessment_findings = findings
    return data
