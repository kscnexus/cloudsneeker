"""Data accuracy rules: status polarity, deduplication, and reconciliation.

These rules decide what counts as exposure, so they are kept apart and pure:

* Polarity comes from the scanner's status, never from the check name or the
  message text. Only ``FAIL`` is exposure; ``PASS`` is evidence of a control
  working; ``MANUAL`` and unknown values are not assessed. Muted findings are
  reported separately and never counted as open.
* Two records are the same finding when provider, account, resource, check,
  scanner, and status match. The most recently seen record is kept and the
  others are listed as merged, so the export still traces to every source.
* Totals must reconcile: status buckets add up to the record count, severity
  buckets add up to the open count, and unique resources are counted apart
  from findings.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from cloudsneeker_api.reports.assessment.model import (
    NOT_ASSESSED,
    STATUS_FAIL,
    STATUS_MANUAL,
    STATUS_PASS,
    STATUS_UNKNOWN,
    NormalizedFinding,
    SourceCoverage,
)
from cloudsneeker_api.reports.schema import SEVERITY_ORDER, empty_severity_counts

# Older results than this are flagged as stale.
DEFAULT_STALE_DAYS = 7

_STATUS_ALIASES: dict[str, str] = {
    "FAIL": STATUS_FAIL,
    "FAILED": STATUS_FAIL,
    "PASS": STATUS_PASS,
    "PASSED": STATUS_PASS,
    "MANUAL": STATUS_MANUAL,
}


def normalize_status(value: Any) -> str:
    """Map a scanner status to ``FAIL``, ``PASS``, ``MANUAL``, or ``UNKNOWN``.

    Args:
        value: Raw status from the record.

    Returns:
        The normalized status. Anything unrecognized is ``UNKNOWN`` so it is
        never counted as either exposure or a passed control.
    """
    return _STATUS_ALIASES.get(str(value or "").strip().upper(), STATUS_UNKNOWN)


def normalize_severity(value: Any) -> str:
    """Return a known severity; unknown values read as ``informational``."""
    text = str(value or "").strip().lower()
    return text if text in SEVERITY_ORDER else "informational"


def dedupe_key(finding: NormalizedFinding) -> tuple[str, ...]:
    """Identity used for deduplication.

    Provider, account, resource, check, scanner, and status. The status is
    part of the key so a pass and a fail of the same check are never merged
    into one record (that conflict is reported, not hidden).
    """
    resource = finding.resource_uid or finding.resource_name or finding.uid
    return (
        finding.provider_type,
        finding.account,
        resource,
        finding.check_id,
        finding.scanner,
        finding.status,
    )


@dataclass
class DedupeResult:
    """Outcome of deduplication.

    Attributes:
        findings: Unique findings.
        input_count: Records before deduplication.
        removed: Records merged into another.
        groups: Unique findings that absorbed at least one duplicate.
    """

    findings: list[NormalizedFinding]
    input_count: int
    removed: int
    groups: int


def _seen(finding: NormalizedFinding) -> datetime:
    return finding.last_seen_at or finding.first_seen_at or datetime.min


def dedupe(findings: Iterable[NormalizedFinding]) -> DedupeResult:
    """Merge records that describe the same finding.

    The most recently seen record survives; the earliest ``first_seen_at`` of
    the group is kept so the age stays honest.

    Args:
        findings: Normalized findings, in any order.

    Returns:
        ``DedupeResult``.
    """
    items = list(findings)
    kept: dict[tuple[str, ...], NormalizedFinding] = {}
    for finding in items:
        key = dedupe_key(finding)
        current = kept.get(key)
        if current is None:
            kept[key] = finding
            continue
        # Latest wins; the source id breaks ties so the result never
        # depends on input order.
        newer, older = (
            (finding, current)
            if (_naive(_seen(finding)), finding.source_id)
            > (_naive(_seen(current)), current.source_id)
            else (current, finding)
        )
        newer.duplicate_source_ids = sorted(
            {
                *newer.duplicate_source_ids,
                *older.duplicate_source_ids,
                older.source_id,
            }
        )
        firsts = [
            value
            for value in (newer.first_seen_at, older.first_seen_at)
            if value is not None
        ]
        if firsts:
            newer.first_seen_at = min(firsts, key=_naive)
        newer.muted = newer.muted and older.muted
        kept[key] = newer
    unique = list(kept.values())
    return DedupeResult(
        findings=unique,
        input_count=len(items),
        removed=len(items) - len(unique),
        groups=sum(1 for item in unique if item.duplicate_source_ids),
    )


def _naive(value: datetime) -> datetime:
    return value.replace(tzinfo=None) if value.tzinfo else value


@dataclass
class PolarityReport:
    """Polarity validation outcome.

    Attributes:
        unknown_status: Records whose status is not pass, fail, or manual.
        manual: Records that need a manual check (not assessed).
        conflicts: Fail records whose resource and check also passed in scope.
        informational_open: Open records whose severity is informational.
        issues: Readable messages for the quality report.
    """

    unknown_status: int = 0
    manual: int = 0
    conflicts: int = 0
    informational_open: int = 0
    issues: list[str] = field(default_factory=list)


def validate_polarity(
    findings: Iterable[NormalizedFinding], *, db_conflicts: int = 0
) -> PolarityReport:
    """Check that exposure comes from status alone and flag ambiguities.

    Args:
        findings: Unique findings.
        db_conflicts: Fail records whose UID also passed in the scans in scope
            (counted in SQL by ``collect``).

    Returns:
        ``PolarityReport``.
    """
    report = PolarityReport(conflicts=db_conflicts)
    by_identity: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for finding in findings:
        if finding.status == STATUS_UNKNOWN:
            report.unknown_status += 1
        elif finding.status == STATUS_MANUAL:
            report.manual += 1
        if finding.is_open and finding.severity == "informational":
            report.informational_open += 1
        identity = dedupe_key(finding)[:-1]
        by_identity[identity].add(finding.status)
    report.conflicts += sum(
        1
        for statuses in by_identity.values()
        if STATUS_FAIL in statuses and STATUS_PASS in statuses
    )
    if report.unknown_status:
        report.issues.append(
            f"{report.unknown_status} record(s) have an unrecognized status and "
            "are excluded from exposure and pass counts."
        )
    if report.conflicts:
        report.issues.append(
            f"{report.conflicts} check result(s) both passed and failed for the "
            "same resource in scope; they are counted as failed."
        )
    return report


@dataclass
class Totals:
    """Reconciled counts over the unique findings.

    Attributes:
        records: Unique non-pass records.
        open: Open (failed, unmuted) findings.
        muted: Failed findings hidden by a mute rule.
        manual: Results that need a manual check.
        unknown: Results with an unrecognized status.
        passed: Passed results (aggregated counts plus pass records).
        pass_records: Pass records present in the finding list.
        open_by_severity: Open findings per severity.
        open_by_area: Open findings per area.
        open_by_category: Open findings per category.
        affected_resources: Distinct resources with at least one open finding.
        affected_resources_by_area: The same, per area.
        checks_failing: Distinct check ids with an open finding.
        fix_available: Open findings with a concrete fix.
    """

    records: int = 0
    open: int = 0
    muted: int = 0
    manual: int = 0
    unknown: int = 0
    passed: int = 0
    pass_records: int = 0
    open_by_severity: dict[str, int] = field(default_factory=empty_severity_counts)
    open_by_area: dict[str, int] = field(default_factory=dict)
    open_by_category: dict[str, int] = field(default_factory=dict)
    affected_resources: int = 0
    affected_resources_by_area: dict[str, int] = field(default_factory=dict)
    checks_failing: int = 0
    fix_available: int = 0


def compute_totals(
    findings: Iterable[NormalizedFinding],
    passed: dict[str, dict[str, int]] | None = None,
) -> Totals:
    """Count unique findings by status, severity, area, and resource.

    Args:
        findings: Unique findings.
        passed: Passed results per area and severity.

    Returns:
        ``Totals``.
    """
    totals = Totals()
    resources: set[str] = set()
    resources_by_area: dict[str, set[str]] = defaultdict(set)
    checks: set[str] = set()
    area_counter: Counter[str] = Counter()
    category_counter: Counter[str] = Counter()
    for finding in findings:
        totals.records += 1
        if finding.status == STATUS_FAIL:
            if finding.muted:
                totals.muted += 1
                continue
            totals.open += 1
            totals.open_by_severity[finding.severity] = (
                totals.open_by_severity.get(finding.severity, 0) + 1
            )
            area_counter[finding.area] += 1
            category_counter[finding.category] += 1
            resources.add(finding.resource_key)
            resources_by_area[finding.area].add(finding.resource_key)
            checks.add(f"{finding.scanner}|{finding.check_id}")
            if finding.fix.get("fix_available"):
                totals.fix_available += 1
        elif finding.status == STATUS_MANUAL:
            totals.manual += 1
        elif finding.status == STATUS_PASS:
            totals.passed += 1
            totals.pass_records += 1
        else:
            totals.unknown += 1
    for by_severity in (passed or {}).values():
        totals.passed += sum(by_severity.values())
    totals.open_by_area = dict(area_counter)
    totals.open_by_category = dict(category_counter)
    totals.affected_resources = len(resources)
    totals.affected_resources_by_area = {
        area: len(items) for area, items in resources_by_area.items()
    }
    totals.checks_failing = len(checks)
    return totals


@dataclass
class ReconciliationCheck:
    """One reconciliation rule and whether it held."""

    rule: str
    ok: bool
    detail: str


def reconcile(totals: Totals) -> list[ReconciliationCheck]:
    """Verify that every total adds up.

    Args:
        totals: Output of ``compute_totals``.

    Returns:
        One ``ReconciliationCheck`` per rule.
    """
    status_sum = (
        totals.open
        + totals.muted
        + totals.manual
        + totals.unknown
        + totals.pass_records
    )
    severity_sum = sum(totals.open_by_severity.values())
    area_sum = sum(totals.open_by_area.values())
    category_sum = sum(totals.open_by_category.values())
    return [
        ReconciliationCheck(
            "status_buckets",
            status_sum == totals.records,
            f"open {totals.open} + muted {totals.muted} + manual {totals.manual} "
            f"+ unknown {totals.unknown} + pass {totals.pass_records} "
            f"= {status_sum}; records {totals.records}",
        ),
        ReconciliationCheck(
            "severity_buckets",
            severity_sum == totals.open,
            f"severity sum {severity_sum}; open {totals.open}",
        ),
        ReconciliationCheck(
            "area_buckets",
            area_sum == totals.open,
            f"area sum {area_sum}; open {totals.open}",
        ),
        ReconciliationCheck(
            "category_buckets",
            category_sum == totals.open,
            f"category sum {category_sum}; open {totals.open}",
        ),
        ReconciliationCheck(
            "resources_le_findings",
            totals.affected_resources <= totals.open,
            f"affected resources {totals.affected_resources}; open {totals.open}",
        ),
    ]


def coverage_state(
    last_assessed_at: datetime | None,
    now: datetime,
    stale_days: int = DEFAULT_STALE_DAYS,
) -> str:
    """Return ``current``, ``stale``, or ``not_assessed`` for one source."""
    if last_assessed_at is None:
        return "not_assessed"
    if now - last_assessed_at > timedelta(days=stale_days):
        return "stale"
    return "current"


def coverage_warnings(
    coverage: Iterable[SourceCoverage], stale_days: int = DEFAULT_STALE_DAYS
) -> list[str]:
    """Readable warnings for stale and missing sources.

    Args:
        coverage: Source coverage rows.
        stale_days: Threshold used to mark a source stale.

    Returns:
        Warnings, one per affected group.
    """
    rows = list(coverage)
    stale = [row for row in rows if row.state == "stale"]
    missing = [row for row in rows if row.state == "not_assessed"]
    warnings: list[str] = []
    if stale:
        names = ", ".join(sorted({row.provider_label for row in stale})[:6])
        warnings.append(
            f"{len(stale)} source(s) were last assessed more than {stale_days} "
            f"days ago ({names}). Their results may not reflect current state."
        )
    if missing:
        names = ", ".join(sorted({row.provider_label for row in missing})[:6])
        warnings.append(
            f"{len(missing)} source(s) in scope have no completed assessment "
            f"({names}). They are shown as {NOT_ASSESSED.lower()}, not as zero findings."
        )
    return warnings


def display_count(value: int | None, assessed: bool) -> str | int:
    """Show a count, or ``Not assessed`` when the source was never assessed."""
    if not assessed or value is None:
        return NOT_ASSESSED
    return value
