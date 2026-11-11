"""Finding lifecycle: reconcile one scan with a target's stored findings.

States (set only here): ``new`` on first detection, ``open`` when seen again,
``fixed`` when a scan that could have reported it did not, ``reopened`` when
a fixed finding returns. Triage (risk accepted, false positive, ...) is a
separate axis kept in ``FindingTriage``.

A finding is marked fixed only when its absence is evidence: the scan
completed, ran the scanner for the finding's category, was not narrowed by
path, package or resource filters, and its severity filter (and "fixed
only" filter) would have let the finding through.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from cloudsneeker_api.appsec import parser
from cloudsneeker_api.appsec.parser import NormalizedFinding, bounded_uid
from cloudsneeker_api.appsec.risk import RiskInput, score_finding

SCANNER_CATEGORY = {
    "vuln": parser.CATEGORY_VULNERABILITY,
    "misconfig": parser.CATEGORY_MISCONFIGURATION,
    "rbac": parser.CATEGORY_MISCONFIGURATION,
    "secret": parser.CATEGORY_SECRET,
    "license": parser.CATEGORY_LICENSE,
    "sast": parser.CATEGORY_CODE,
}

# Options that narrow what a scan looks at; with any of them set, a missing
# finding may simply be out of scope.
NARROWING_OPTIONS = (
    "skip_dirs",
    "skip_files",
    "pkg_types",
    "pkg_relationships",
    "ignore_statuses",
    "misconfig_scanners",
    "include_namespaces",
    "exclude_namespaces",
    "include_kinds",
    "exclude_kinds",
    "skip_images",
    "ignored_licenses",
)

BATCH = 500

STATE_NEW = "new"
STATE_OPEN = "open"
STATE_REOPENED = "reopened"
STATE_FIXED = "fixed"


@dataclass
class Coverage:
    """What a scan was able to report."""

    categories: set[str] = field(default_factory=set)
    # Product-scale severities the scan reports; ``None`` means all.
    severities: set[str] | None = None
    fixed_only: bool = False
    complete: bool = True
    reasons: list[str] = field(default_factory=list)

    def establishes_absence(self, category: str, severity: str, fix_available) -> bool:
        """True when a finding missing from this scan can be called fixed."""
        if not self.complete or category not in self.categories:
            return False
        if self.severities is not None and severity not in self.severities:
            return False
        if (
            self.fixed_only
            and category == parser.CATEGORY_VULNERABILITY
            and not fix_available
        ):
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "categories": sorted(self.categories),
            "severities": (
                sorted(self.severities) if self.severities is not None else None
            ),
            "fixed_only": self.fixed_only,
            "complete": self.complete,
            "reasons": self.reasons,
        }


def coverage_for(
    options: dict[str, Any], *, complete: bool = True, reasons: list[str] | None = None
) -> Coverage:
    """Build the coverage of a scan from its resolved options.

    Args:
        options: Validated scan options (``scanners`` and filters).
        complete: False when part of the scan failed (an image of a list, a
            cluster resource).
        reasons: Why the scan is incomplete.
    """
    coverage = Coverage(complete=complete, reasons=list(reasons or []))
    for scanner in options.get("scanners") or []:
        category = SCANNER_CATEGORY.get(scanner)
        if category:
            coverage.categories.add(category)
    severities = options.get("severities")
    if severities:
        coverage.severities = {parser.normalize_severity(item) for item in severities}
    coverage.fixed_only = bool(options.get("ignore_unfixed"))
    narrowed = [name for name in NARROWING_OPTIONS if options.get(name)]
    if narrowed:
        coverage.complete = False
        coverage.reasons.append(
            "The scan was narrowed by: " + ", ".join(narrowed) + "."
        )
    return coverage


@dataclass
class Reconciliation:
    new: int = 0
    reopened: int = 0
    still_open: int = 0
    fixed: int = 0
    suppressed: int = 0
    uids: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, int]:
        return {
            "new": self.new,
            "reopened": self.reopened,
            "open": self.still_open,
            "fixed": self.fixed,
            "suppressed": self.suppressed,
        }


@dataclass(frozen=True)
class AppContext:
    """Application facts the priority score reads."""

    criticality: str | None = None
    environment: str | None = None
    internet_exposed: bool | None = None


def next_state(current: str | None) -> str:
    """State of a finding a scan just reported."""
    if current is None:
        return STATE_NEW
    if current == STATE_FIXED:
        return STATE_REOPENED
    return STATE_OPEN


def assign_uid(legacy_uid: str, fingerprint: str, taken: set[str]) -> str:
    """Return a tenant-unique UID, keeping the legacy UID when it is free."""
    base = legacy_uid or f"appsec-{fingerprint[:32]}"
    if base not in taken:
        return base
    return bounded_uid(f"{base[:280]}-{fingerprint[:12]}")


_COLUMN_FIELDS = (
    "category",
    "finding_type",
    "scanner",
    "title",
    "description",
    "severity",
    "source_severity",
    "rule_id",
    "pkg_name",
    "pkg_version",
    "fixed_version",
    "ecosystem",
    "purl",
    "location",
    "file_path",
    "start_line",
    "end_line",
    "resource",
    "primary_url",
    "cvss_score",
    "fix_available",
    "suppressed",
    "suppression",
)
_UPDATE_FIELDS = (
    *_COLUMN_FIELDS,
    "details",
    "state",
    "priority",
    "priority_score",
    "priority_factors",
    "last_seen_at",
    "fixed_at",
    "due_at",
    "reopen_count",
    "last_run",
    "updated_at",
)
_RESCORE_FIELDS = ["priority", "priority_score", "priority_factors", "due_at"]


def _details(finding: NormalizedFinding) -> dict[str, Any]:
    details = dict(finding.details)
    if finding.direct_dependency is not None:
        details["direct_dependency"] = finding.direct_dependency
    return details


def _score(row, context: AppContext, risk_config, now: datetime):
    return score_finding(
        RiskInput(
            category=row.category,
            severity=row.severity,
            cvss_score=row.cvss_score,
            epss_score=row.epss_score,
            known_exploited=row.known_exploited,
            fix_available=row.fix_available,
            direct_dependency=(row.details or {}).get("direct_dependency"),
            criticality=context.criticality,
            environment=context.environment,
            internet_exposed=context.internet_exposed,
            first_seen_at=row.first_seen_at,
            now=now,
        ),
        risk_config,
    )


def reconcile(
    *,
    tenant_id: str,
    target,
    run,
    findings: list[NormalizedFinding],
    coverage: Coverage,
    now: datetime,
    risk_config: dict[str, Any],
    sla_days: dict[str, int],
    context: AppContext | None = None,
    using: str | None = None,
) -> Reconciliation:
    """Apply one scan's findings to the target's stored findings.

    Must run inside a transaction on ``using``.

    Args:
        tenant_id: Tenant of the target.
        target: ``TrivyTarget``.
        run: ``TrivyRun`` that produced the findings.
        findings: Parser output, unique by fingerprint.
        coverage: What the scan could report.
        now: Scan completion time.
        risk_config: Full risk config.
        sla_days: Days to fix by severity.
        context: Application facts for the score.
        using: Database alias.

    Returns:
        Counts per transition and the UID given to each fingerprint.
    """
    from cloudsneeker_api.models import AppSecFinding, AppSecFindingEvent

    context = context or AppContext()
    manager = AppSecFinding.objects.using(using) if using else AppSecFinding.objects
    events_manager = (
        AppSecFindingEvent.objects.using(using) if using else AppSecFindingEvent.objects
    )
    existing = {
        row.fingerprint: row
        for row in manager.filter(
            tenant_id=tenant_id, target=target
        ).select_for_update()
    }
    reported = {finding.fingerprint: finding for finding in findings}

    candidates = sorted(
        {
            finding.legacy_uid
            for fingerprint, finding in reported.items()
            if fingerprint not in existing and finding.legacy_uid
        }
    )
    taken: set[str] = set()
    for start in range(0, len(candidates), BATCH):
        taken.update(
            manager.filter(
                tenant_id=tenant_id, uid__in=candidates[start : start + BATCH]
            ).values_list("uid", flat=True)
        )

    result = Reconciliation()
    events: list[Any] = []
    to_create: list[Any] = []
    to_update: list[Any] = []

    def event(row, kind: str, detail: dict[str, Any] | None = None) -> None:
        events.append(
            AppSecFindingEvent(
                tenant_id=tenant_id,
                finding=row,
                run=run,
                kind=kind,
                detail=detail or {},
            )
        )

    for fingerprint in sorted(reported):
        finding = reported[fingerprint]
        row = existing.get(fingerprint)
        created = row is None
        if created:
            uid = assign_uid(finding.legacy_uid, fingerprint, taken)
            taken.add(uid)
            row = AppSecFinding(
                tenant_id=tenant_id,
                target=target,
                fingerprint=fingerprint,
                uid=uid,
                first_seen_at=now,
                first_run=run,
            )
        else:
            if row.severity != finding.severity:
                event(
                    row,
                    "severity_changed",
                    {"from": row.severity, "to": finding.severity},
                )
            if row.suppressed != finding.suppressed:
                event(
                    row,
                    "suppressed" if finding.suppressed else "unsuppressed",
                    finding.suppression,
                )
        previous_state = None if created else row.state
        for name in _COLUMN_FIELDS:
            setattr(row, name, getattr(finding, name))
        row.details = _details(finding)
        row.state = next_state(previous_state)
        row.last_seen_at = now
        row.last_run = run
        row.fixed_at = None
        row.updated_at = now
        if row.state == STATE_REOPENED:
            row.reopen_count += 1
        days = sla_days.get(row.severity)
        row.due_at = row.first_seen_at + timedelta(days=days) if days else None
        scored = _score(row, context, risk_config, now)
        row.priority, row.priority_score = scored.priority, scored.score
        row.priority_factors = scored.factors
        result.uids[fingerprint] = row.uid

        if finding.suppressed:
            result.suppressed += 1
        if created:
            to_create.append(row)
            result.new += 1
            event(row, "detected", {"severity": row.severity})
            if finding.suppressed:
                event(row, "suppressed", finding.suppression)
        else:
            to_update.append(row)
            if row.state == STATE_REOPENED:
                result.reopened += 1
                event(row, "reopened", {"reopen_count": row.reopen_count})
            else:
                result.still_open += 1

    for fingerprint, row in existing.items():
        if fingerprint in reported or row.state == STATE_FIXED:
            continue
        if not coverage.establishes_absence(
            row.category, row.severity, row.fix_available
        ):
            continue
        row.state = STATE_FIXED
        row.fixed_at = now
        row.updated_at = now
        to_update.append(row)
        result.fixed += 1
        event(row, "fixed", {})

    for start in range(0, len(to_create), BATCH):
        manager.bulk_create(to_create[start : start + BATCH])
    for start in range(0, len(to_update), BATCH):
        manager.bulk_update(to_update[start : start + BATCH], _UPDATE_FIELDS)
    for start in range(0, len(events), BATCH):
        events_manager.bulk_create(events[start : start + BATCH])
    return result


def rescore_findings(
    *,
    queryset,
    context_for_target,
    risk_config: dict[str, Any],
    sla_days: dict[str, int],
    now: datetime,
) -> int:
    """Recompute priority and deadline after settings or an application change.

    Args:
        queryset: Findings to rescore (already tenant scoped).
        context_for_target: Callable ``target_id -> AppContext``.
        risk_config: Full risk config.
        sla_days: Days to fix by severity.
        now: Current time.

    Returns:
        Number of findings updated.
    """
    manager = queryset.model.objects.using(queryset.db)
    updated = 0
    batch: list[Any] = []
    for row in queryset.iterator(chunk_size=BATCH):
        scored = _score(row, context_for_target(row.target_id), risk_config, now)
        days = sla_days.get(row.severity)
        row.priority, row.priority_score = scored.priority, scored.score
        row.priority_factors = scored.factors
        row.due_at = row.first_seen_at + timedelta(days=days) if days else None
        batch.append(row)
        if len(batch) >= BATCH:
            manager.bulk_update(batch, _RESCORE_FIELDS)
            updated += len(batch)
            batch = []
    if batch:
        manager.bulk_update(batch, _RESCORE_FIELDS)
        updated += len(batch)
    return updated
