"""Scores, grades, and KPIs for assessment reports.

The score formula is the one the existing reports use
(``reports.data.common.security_score``) so a grade means the same thing in
every report:

* With passed results (cloud posture), it is the severity-weighted share of
  results that passed.
* With failures only (vulnerabilities, secrets, policy matches, where scanners
  never emit a pass), it decays with the weighted open count.

An area with no assessed source has no score (``None``), never zero. The
overall score is the weighted mean of the areas that were assessed; the
weights are renormalized over those areas and the report says which were
left out.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from statistics import median
from typing import Any

from cloudsneeker_api.reports.assessment.accuracy import Totals
from cloudsneeker_api.reports.assessment.model import (
    AREA_APPSEC,
    AREA_CLOUD,
    AREA_GOVERNANCE,
    AREA_LABELS,
    NOT_ASSESSED,
    NormalizedFinding,
)
from cloudsneeker_api.reports.data.common import (
    SEVERITY_WEIGHTS,
    grade_for,
    security_score,
)
from cloudsneeker_api.reports.schema import SEVERITY_ORDER, empty_severity_counts

AREA_WEIGHTS: dict[str, float] = {
    AREA_CLOUD: 0.45,
    AREA_APPSEC: 0.35,
    AREA_GOVERNANCE: 0.20,
}


def area_scores(
    findings: Iterable[NormalizedFinding],
    passed: dict[str, dict[str, int]],
    assessed_areas: set[str],
) -> dict[str, float | None]:
    """Score every area; areas without an assessed source score ``None``.

    Args:
        findings: Unique findings.
        passed: Passed results per area and severity.
        assessed_areas: Areas with at least one completed assessment.

    Returns:
        Area key to score.
    """
    fail: dict[str, dict[str, int]] = {
        area: empty_severity_counts() for area in AREA_WEIGHTS
    }
    for finding in findings:
        if finding.is_open and finding.area in fail:
            fail[finding.area][finding.severity] += 1
    scores: dict[str, float | None] = {}
    for area in AREA_WEIGHTS:
        if area not in assessed_areas:
            scores[area] = None
            continue
        area_pass = passed.get(area) or empty_severity_counts()
        score = security_score(fail[area], area_pass)
        # Assessed with nothing open and no pass records: a clean result.
        scores[area] = 100.0 if score is None else score
    return scores


def overall_score(scores: dict[str, float | None]) -> float | None:
    """Weighted mean over assessed areas (``None`` when none was assessed)."""
    weighted = 0.0
    weights = 0.0
    for area, score in scores.items():
        if score is None:
            continue
        weight = AREA_WEIGHTS.get(area, 0.0)
        weighted += weight * score
        weights += weight
    if not weights:
        return None
    return round(weighted / weights, 1)


def risk_index(by_severity: dict[str, int]) -> float:
    """Severity-weighted open count (same weights as the score)."""
    return sum(
        SEVERITY_WEIGHTS.get(sev, 0.0) * count for sev, count in by_severity.items()
    )


def _age_days(finding: NormalizedFinding, now: datetime) -> float | None:
    if finding.first_seen_at is None:
        return None
    return max(0.0, (now - finding.first_seen_at).total_seconds() / 86400.0)


def kpis(
    findings: list[NormalizedFinding],
    totals: Totals,
    *,
    now: datetime,
    sources_assessed: int,
    sources_in_scope: int,
    frameworks_assessed: int,
) -> dict[str, Any]:
    """Headline numbers, each traceable to the unique finding set.

    Args:
        findings: Unique findings.
        totals: Reconciled totals of ``findings``.
        now: Report time (ages are measured from it).
        sources_assessed: Sources with a completed assessment.
        sources_in_scope: Sources the scope expected.
        frameworks_assessed: Frameworks with requirement results.

    Returns:
        KPI mapping. Values that cannot be measured read ``Not assessed``.
    """
    urgent = [
        finding
        for finding in findings
        if finding.is_open and finding.severity in ("critical", "high")
    ]
    ages = [age for age in (_age_days(item, now) for item in urgent) if age is not None]
    open_count = totals.open
    return {
        "open_findings": open_count,
        "affected_resources": totals.affected_resources,
        "critical": totals.open_by_severity.get("critical", 0),
        "high": totals.open_by_severity.get("high", 0),
        "medium": totals.open_by_severity.get("medium", 0),
        "low": totals.open_by_severity.get("low", 0),
        "passed_results": totals.passed,
        "muted": totals.muted,
        "manual_review": totals.manual,
        "failing_checks": totals.checks_failing,
        "fix_available_pct": (
            round(100.0 * totals.fix_available / open_count, 1) if open_count else None
        ),
        "median_age_critical_high_days": round(median(ages), 1) if ages else None,
        "sources_assessed": sources_assessed,
        "sources_in_scope": sources_in_scope,
        "coverage_pct": (
            round(100.0 * sources_assessed / sources_in_scope, 1)
            if sources_in_scope
            else None
        ),
        "frameworks_assessed": frameworks_assessed,
        "risk_index": round(risk_index(totals.open_by_severity), 1),
    }


def area_summary(
    area: str, score: float | None, totals_for_area: Totals, assessed: bool
) -> dict[str, Any]:
    """Summary row of one area for the posture table."""
    if not assessed:
        return {
            "area": area,
            "label": AREA_LABELS[area],
            "assessed": False,
            "score": None,
            "grade": "N/A",
            "open_findings": NOT_ASSESSED,
            "affected_resources": NOT_ASSESSED,
            "critical": NOT_ASSESSED,
            "high": NOT_ASSESSED,
        }
    return {
        "area": area,
        "label": AREA_LABELS[area],
        "assessed": True,
        "score": score,
        "grade": grade_for(score),
        "open_findings": totals_for_area.open,
        "affected_resources": totals_for_area.affected_resources,
        "critical": totals_for_area.open_by_severity.get("critical", 0),
        "high": totals_for_area.open_by_severity.get("high", 0),
    }


def severity_rank(severity: str) -> int:
    """Index of a severity, critical first."""
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


__all__ = [
    "AREA_WEIGHTS",
    "area_scores",
    "area_summary",
    "grade_for",
    "kpis",
    "overall_score",
    "risk_index",
    "severity_rank",
]
