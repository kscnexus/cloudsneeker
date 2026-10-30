"""Executive summary report data (management audience)."""

from __future__ import annotations

from typing import Any

from cloudsneeker_api.reports.catalog import EXECUTIVE
from cloudsneeker_api.reports.data import governance
from cloudsneeker_api.reports.data.common import (
    CLOUD_SCOPE,
    SECRET_Q,
    FindingStats,
    ScanScope,
    aggregate_findings,
    average_pass_pct,
    compliance_posture,
    findings_for,
    grade_for,
    latest_scan_ids,
    merge_stats,
    risk_table,
    security_score,
    top_risks,
    trend,
)
from cloudsneeker_api.reports.data.compliance import compliance_scan_ids
from cloudsneeker_api.reports.schema import ReportData, ReportFilters, ReportTable
from cloudsneeker_api.services.finding_triage import triage_counts
from django.utils import timezone

APPSEC_SCOPE = ScanScope(
    trivy_modes=frozenset({"iac", "image", "fs", "repo", "sbom", "k8s", "sast"}),
    prowler_provider_types=frozenset({"iac", "image"}),
)
ALL_SCOPE = ScanScope(
    cloud=True,
    trivy_modes=APPSEC_SCOPE.trivy_modes,
    prowler_provider_types=APPSEC_SCOPE.prowler_provider_types,
)

# Relative weight of each domain in the overall score.
DOMAIN_WEIGHTS: dict[str, float] = {
    "cloud": 0.4,
    "application": 0.3,
    "compliance": 0.2,
    "governance": 0.1,
}

DOMAIN_LABELS: dict[str, str] = {
    "cloud": "Cloud posture",
    "application": "Application security",
    "compliance": "Compliance",
    "governance": "Cloud governance",
}

DOMAIN_COLUMNS: list[tuple[str, str]] = [
    ("label", "Area"),
    ("grade", "Grade"),
    ("score", "Score"),
    ("open_issues", "Open issues"),
    ("critical", "Critical"),
    ("high", "High"),
    ("coverage", "Coverage"),
]


def overall_score(domain_scores: dict[str, float | None]) -> float | None:
    """Weighted average of the domains that have data.

    Args:
        domain_scores: Domain key to score (``None`` means no data).

    Returns:
        Score 0-100 or ``None`` when no domain has data.
    """
    weighted = 0.0
    weights = 0.0
    for domain, score in domain_scores.items():
        if score is None:
            continue
        weight = DOMAIN_WEIGHTS.get(domain, 0.0)
        weighted += weight * score
        weights += weight
    if weights == 0:
        return None
    return round(weighted / weights, 1)


def executive_headline(
    grade: str,
    score: float | None,
    open_issues: int,
    critical: int,
    high: int,
    sources: int,
    compliance_pct: float | None,
) -> str:
    """Return the plain-language headline for management readers."""
    if score is None:
        return (
            "No completed scans in scope yet. Connect a cloud account or "
            "repository and run a scan to get your security grade."
        )
    parts = [f"Overall security grade {grade} ({score:.0f}/100)."]
    if open_issues == 0:
        parts.append(f"No open issues across {sources} source(s).")
    else:
        parts.append(
            f"{open_issues} open issue(s) across {sources} source(s), "
            f"{critical} critical and {high} high."
        )
    if compliance_pct is not None:
        parts.append(f"Compliance averages {compliance_pct:.0f}%.")
    if critical or high:
        parts.append("Fixing the top five risks below removes the most exposure.")
    return " ".join(parts)


def next_actions(
    *,
    cloud: FindingStats,
    application: FindingStats,
    secrets_open: int,
    posture: list[dict[str, Any]],
    governance_kpis: dict[str, Any],
    risks: list[dict[str, Any]],
    has_cloud: bool,
    has_application: bool,
) -> list[dict[str, Any]]:
    """Return prioritized, plain-language next actions.

    Args:
        cloud: Cloud finding stats.
        application: Application security finding stats.
        secrets_open: Open secret findings across sources.
        posture: Compliance posture rows (weakest first).
        governance_kpis: Governance KPIs (empty without governance data).
        risks: Ranked top risks.
        has_cloud: Whether any cloud scan is in scope.
        has_application: Whether any application security scan is in scope.

    Returns:
        Actions ``{"priority", "action", "why"}``.
    """
    actions: list[tuple[str, str]] = []
    critical = cloud.fail_by_severity["critical"] + application.fail_by_severity["critical"]
    if critical and risks:
        actions.append(
            (
                f"Fix the {critical} critical issue(s), starting with "
                f"'{risks[0].get('title') or risks[0]['check_id']}'.",
                "Critical issues are the most likely path to a breach.",
            )
        )
    if secrets_open:
        actions.append(
            (
                f"Rotate and remove the {secrets_open} exposed secret(s).",
                "Leaked credentials give attackers direct access.",
            )
        )
    weakest = next((item for item in posture if item["pass_pct"] is not None), None)
    if weakest and weakest["pass_pct"] < 80:
        actions.append(
            (
                f"Close compliance gaps in {weakest['compliance_id']} "
                f"({weakest['pass_pct']:.0f}% passing).",
                "Audit findings and customer questionnaires rely on this framework.",
            )
        )
    high = cloud.fail_by_severity["high"] + application.fail_by_severity["high"]
    if high:
        actions.append(
            (
                f"Schedule remediation of the {high} high-severity issue(s) this sprint.",
                "High issues often combine into a critical attack path.",
            )
        )
    if governance_kpis.get("policies_with_matches"):
        actions.append(
            (
                f"Review the {governance_kpis['matched_resources']} resource(s) "
                "flagged by governance policies.",
                "Policy drift adds cost and risk over time.",
            )
        )
    if not has_cloud:
        actions.append(
            (
                "Connect your cloud accounts and schedule daily scans.",
                "Without cloud coverage the grade only reflects application code.",
            )
        )
    if not has_application:
        actions.append(
            (
                "Add repositories and container images to Application Security.",
                "Most breaches start in code and dependencies, not only in the cloud.",
            )
        )
    if not actions:
        actions.append(
            (
                "Keep scans scheduled and review this report monthly.",
                "No urgent issues are open; continuous coverage keeps it that way.",
            )
        )
    return [
        {"priority": index, "action": action, "why": why}
        for index, (action, why) in enumerate(actions[:6], start=1)
    ]


def assemble(tenant_id: str, filters: ReportFilters) -> ReportData:
    """Assemble the executive summary.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters.

    Returns:
        ``ReportData`` with domain grades, top five risks, compliance, trend,
        and recommended next actions.
    """
    data = ReportData(
        report_type=EXECUTIVE,
        title="Executive Security Summary",
        generated_at=timezone.now(),
        filters=filters,
    )
    cloud_ids = latest_scan_ids(tenant_id, filters, CLOUD_SCOPE)
    app_ids = latest_scan_ids(tenant_id, filters, APPSEC_SCOPE)
    cloud_stats = (
        aggregate_findings(findings_for(tenant_id, cloud_ids, filters))
        if cloud_ids
        else FindingStats()
    )
    app_stats = (
        aggregate_findings(findings_for(tenant_id, app_ids, filters))
        if app_ids
        else FindingStats()
    )
    all_ids = [*cloud_ids, *app_ids]
    secrets_open = (
        aggregate_findings(
            findings_for(tenant_id, all_ids, filters, include_q=SECRET_Q)
        ).status["fail"]
        if all_ids
        else 0
    )
    posture = compliance_posture(tenant_id, compliance_scan_ids(tenant_id, filters))
    compliance_pct = average_pass_pct(posture)
    governance_data = governance.assemble(tenant_id, filters)

    domain_scores = {
        "cloud": security_score(cloud_stats.fail_by_severity, cloud_stats.pass_by_severity),
        "application": security_score(
            app_stats.fail_by_severity, app_stats.pass_by_severity
        ),
        "compliance": compliance_pct,
        "governance": governance_data.score,
    }
    combined = merge_stats([cloud_stats, app_stats])
    data.score = overall_score(domain_scores)
    data.grade = grade_for(data.score)
    data.severity_totals = dict(combined.fail_by_severity)
    data.status_totals = dict(combined.status)

    risks = top_risks(findings_for(tenant_id, all_ids, filters), limit=5) if all_ids else []
    data.top_risks = risks
    data.compliance = posture
    data.trend = trend(tenant_id, filters, ALL_SCOPE)

    domain_rows = [
        _domain_row("cloud", domain_scores["cloud"], cloud_stats, f"{len(cloud_ids)} account(s)"),
        _domain_row(
            "application",
            domain_scores["application"],
            app_stats,
            f"{len(app_ids)} target(s)",
        ),
        {
            "domain": "compliance",
            "label": DOMAIN_LABELS["compliance"],
            "score": compliance_pct,
            "grade": grade_for(compliance_pct),
            "open_issues": sum(item["failed"] for item in posture),
            "critical": 0,
            "high": 0,
            "coverage": f"{len(posture)} framework(s)",
        },
        {
            "domain": "governance",
            "label": DOMAIN_LABELS["governance"],
            "score": governance_data.score,
            "grade": governance_data.grade,
            "open_issues": governance_data.kpis.get("matched_resources", 0),
            "critical": 0,
            "high": 0,
            "coverage": f"{governance_data.kpis.get('policies_evaluated', 0)} policy(ies)",
        },
    ]
    data.sources = domain_rows

    sources_count = len(cloud_ids) + len(app_ids)
    data.kpis = {
        "overall_score": data.score,
        "grade": data.grade,
        "open_issues": combined.status["fail"],
        "critical": combined.fail_by_severity["critical"],
        "high": combined.fail_by_severity["high"],
        "secrets_open": secrets_open,
        "compliance_pct": compliance_pct,
        "sources_in_scope": sources_count,
        "governance_matched_resources": governance_data.kpis.get("matched_resources", 0),
    }
    triage = finding_triage_summary(tenant_id, all_ids, filters)
    data.kpis.update(
        {
            "triage_in_progress": triage["in_progress"],
            "triage_resolved": triage["resolved"],
            "triage_false_positive": triage["false_positive"],
        }
    )
    data.extra["triage"] = triage
    data.headline = executive_headline(
        data.grade,
        data.score,
        combined.status["fail"],
        combined.fail_by_severity["critical"],
        combined.fail_by_severity["high"],
        sources_count,
        compliance_pct,
    )
    data.remediation = next_actions(
        cloud=cloud_stats,
        application=app_stats,
        secrets_open=secrets_open,
        posture=posture,
        governance_kpis=governance_data.kpis,
        risks=risks,
        has_cloud=bool(cloud_ids),
        has_application=bool(app_ids),
    )
    data.extra["domain_scores"] = domain_scores
    if data.score is None and governance_data.is_empty:
        data.empty_state = data.headline

    data.tables = [
        ReportTable(
            key="domains",
            title="Security by area",
            columns=DOMAIN_COLUMNS,
            rows=domain_rows,
            total=len(domain_rows),
        ),
        risk_table(risks),
        ReportTable(
            key="compliance",
            title="Compliance posture",
            columns=[
                ("compliance_id", "Framework"),
                ("pass_pct", "Passing %"),
                ("passed", "Passed"),
                ("failed", "Failed"),
                ("manual", "Manual"),
            ],
            rows=posture,
            total=len(posture),
        ),
    ]
    return data


def finding_triage_summary(
    tenant_id: str, scan_ids: list, filters: ReportFilters
) -> dict[str, Any]:
    """Triage counts for the findings in scope.

    Counts triage rows whose finding UID appears in the in-scope scans.
    ``in_progress`` adds ``under_review`` and ``remediating``. Open-issue
    counts and the score are unchanged: false positives still count as open
    until they are muted (follow-up in ``knowledge-base/finding-triage.md``).

    Args:
        tenant_id: Tenant UUID string.
        scan_ids: In-scope scan ids.
        filters: Report filters.

    Returns:
        ``{"by_status": {...}, "in_progress", "resolved", "false_positive",
        "risk_accepted", "triaged"}``.
    """
    if not scan_ids:
        counts = triage_counts(tenant_id, [])
    else:
        counts = triage_counts(
            tenant_id, findings_for(tenant_id, scan_ids, filters).values("uid")
        )
    return {
        "by_status": counts,
        "in_progress": counts["under_review"] + counts["remediating"],
        "resolved": counts["resolved"],
        "false_positive": counts["false_positive"],
        "risk_accepted": counts["risk_accepted"],
        "triaged": sum(counts.values()) - counts["open"],
    }


def _domain_row(
    domain: str, score: float | None, stats: FindingStats, coverage: str
) -> dict[str, Any]:
    return {
        "domain": domain,
        "label": DOMAIN_LABELS[domain],
        "score": score,
        "grade": grade_for(score),
        "open_issues": stats.status["fail"],
        "critical": stats.fail_by_severity["critical"],
        "high": stats.fail_by_severity["high"],
        "coverage": coverage,
    }
