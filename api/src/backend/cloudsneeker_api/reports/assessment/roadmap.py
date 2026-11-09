"""Issue groups, top risks, and the remediation roadmap.

Open findings are grouped by issue (scanner and check id): one roadmap item
fixes one issue everywhere it occurs. Each group keeps the references of its
findings so the appendix and the CSV trace back to every record.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from cloudsneeker_api.reports.assessment.model import NormalizedFinding
from cloudsneeker_api.reports.assessment.recommend import (
    PRIORITIES,
    WINDOWS,
    GroupStats,
    recommend,
)
from cloudsneeker_api.reports.assessment.scoring import severity_rank

# Roadmap rows printed per window; the rest stay in the appendix and CSV.
MAX_ITEMS_PER_WINDOW = 25
MAX_REFS_PER_ITEM = 6


@dataclass
class IssueGroup:
    """Open findings of one issue.

    Attributes:
        key: ``scanner|check_id``.
        lead: Representative finding (most severe, then most recent).
        findings: Every open finding of the issue.
        stats: Spread of the issue.
        recommendation: Output of ``recommend`` for the lead finding.
    """

    key: str
    lead: NormalizedFinding
    findings: list[NormalizedFinding] = field(default_factory=list)
    stats: GroupStats = field(default_factory=GroupStats)
    recommendation: dict[str, Any] = field(default_factory=dict)

    @property
    def priority(self) -> str | None:
        return self.recommendation.get("priority")


def _lead_key(finding: NormalizedFinding) -> tuple:
    seen = finding.last_seen_at.timestamp() if finding.last_seen_at else 0.0
    return (severity_rank(finding.severity), -seen, finding.ref)


def assign_refs(findings: list[NormalizedFinding]) -> None:
    """Give every finding a stable ``F-0001`` reference.

    Ordered by severity, area, check, resource, and source id so the same data
    always gets the same references.
    """
    ordered = sorted(
        findings,
        key=lambda item: (
            severity_rank(item.severity),
            item.area,
            item.check_id,
            item.resource_key,
            item.source_id,
        ),
    )
    width = max(4, len(str(len(ordered))))
    for index, finding in enumerate(ordered, start=1):
        finding.ref = f"F-{index:0{width}d}"


def issue_groups(
    findings: Iterable[NormalizedFinding], *, now: datetime
) -> list[IssueGroup]:
    """Group open findings by issue and rank the groups.

    Ranking: priority, severity, affected resources, findings, check id.

    Args:
        findings: Unique findings with references assigned.
        now: Report time.

    Returns:
        Ranked ``IssueGroup`` list.
    """
    groups: dict[str, IssueGroup] = {}
    for finding in findings:
        if not finding.is_open:
            continue
        key = f"{finding.scanner}|{finding.check_id}"
        group = groups.get(key)
        if group is None:
            groups[key] = IssueGroup(key=key, lead=finding, findings=[finding])
            continue
        group.findings.append(finding)
        if _lead_key(finding) < _lead_key(group.lead):
            group.lead = finding
    for group in groups.values():
        firsts = [item.first_seen_at for item in group.findings if item.first_seen_at]
        group.stats = GroupStats(
            findings=len(group.findings),
            resources=len({item.resource_key for item in group.findings}),
            accounts=len(
                {(item.provider_type, item.account) for item in group.findings}
            ),
            oldest_first_seen=min(firsts) if firsts else None,
        )
        group.recommendation = recommend(group.lead, group.stats, now=now)
    return sorted(
        groups.values(),
        key=lambda group: (
            PRIORITIES.index(group.priority) if group.priority in PRIORITIES else 9,
            severity_rank(group.lead.severity),
            -group.stats.resources,
            -group.stats.findings,
            group.lead.check_id,
        ),
    )


def group_row(group: IssueGroup) -> dict[str, Any]:
    """Flat row of one issue group for tables and exports."""
    lead = group.lead
    rec = group.recommendation
    refs = sorted(item.ref for item in group.findings)
    shown = refs[:MAX_REFS_PER_ITEM]
    extra = len(refs) - len(shown)
    return {
        "priority": rec.get("priority") or "-",
        "window": rec.get("window") or "Not scheduled",
        "refs": ", ".join(shown) + (f" (+{extra} more)" if extra > 0 else ""),
        "lead_ref": lead.ref,
        "severity": lead.severity,
        "area": lead.area,
        "category": lead.category,
        "check_id": lead.check_id,
        "title": rec.get("title") or lead.check_id,
        "resource": lead.resource_name or lead.resource_uid,
        "resources": group.stats.resources,
        "findings": group.stats.findings,
        "accounts": group.stats.accounts,
        "justification": rec.get("justification", ""),
        "instructions": " ".join(rec.get("instructions") or []),
        "suggested_owner": rec.get("suggested_owner", ""),
        "sla_days": rec.get("sla_days"),
        "target_date": rec.get("target_date"),
        "validation": " ".join(rec.get("validation") or []),
        "expected_outcome": rec.get("expected_outcome", ""),
    }


def roadmap(groups: list[IssueGroup]) -> list[dict[str, Any]]:
    """Remediation roadmap: one window per priority, with bounded items.

    Args:
        groups: Ranked issue groups.

    Returns:
        Windows ``{"priority", "id", "label", "items", "total_items",
        "total_findings", "total_resources"}``.
    """
    windows = []
    for priority in PRIORITIES:
        members = [group for group in groups if group.priority == priority]
        windows.append(
            {
                "priority": priority,
                "id": WINDOWS[priority]["id"],
                "label": WINDOWS[priority]["label"],
                "items": [group_row(group) for group in members[:MAX_ITEMS_PER_WINDOW]],
                "total_items": len(members),
                "total_findings": sum(group.stats.findings for group in members),
                "total_resources": sum(group.stats.resources for group in members),
            }
        )
    return windows


def top_risks(groups: list[IssueGroup], limit: int = 10) -> list[dict[str, Any]]:
    """The highest-ranked issues with their full recommendation."""
    risks = []
    for group in groups[:limit]:
        if group.priority is None:
            continue
        risks.append(
            {
                **group_row(group),
                "recommendation": group.recommendation,
            }
        )
    return risks
