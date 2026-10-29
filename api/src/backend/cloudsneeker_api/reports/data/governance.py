"""Cloud governance (Custodian dry-run) report data."""

from __future__ import annotations

from typing import Any

from cloudsneeker_api.models import CustodianRun
from cloudsneeker_api.reports.catalog import GOVERNANCE
from cloudsneeker_api.reports.data.common import grade_for, provider_label
from cloudsneeker_api.reports.schema import ReportData, ReportFilters, ReportTable
from django.utils import timezone

POLICY_COLUMNS: list[tuple[str, str]] = [
    ("policy", "Policy"),
    ("provider", "Provider"),
    ("provider_type", "Type"),
    ("resources", "Matched resources"),
    ("new", "New since last run"),
    ("resolved", "Resolved since last run"),
    ("finished_at", "Last run"),
]

RESOURCE_COLUMNS: list[tuple[str, str]] = [
    ("policy", "Policy"),
    ("provider", "Provider"),
    ("uid", "Resource"),
    ("name", "Name"),
    ("type", "Type"),
    ("region", "Region"),
]

EMPTY_STATE = (
    "No completed Cloud Governance dry-runs in scope. Create a policy in Cloud "
    "Governance and run it to populate this report."
)


def latest_runs(tenant_id: str, filters: ReportFilters) -> list[CustodianRun]:
    """Return the latest completed dry-run of every policy in scope.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters (providers and date window on ``finished_at``).

    Returns:
        Runs ordered by matched resources, most first.
    """
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
    runs = list(
        queryset.select_related("policy", "provider")
        .order_by("policy_id", "-finished_at", "-inserted_at")
        .distinct("policy_id")
    )
    return sorted(runs, key=lambda run: -_resource_count(run))


def _resource_count(run: CustodianRun) -> int:
    try:
        return int((run.summary or {}).get("resource_count") or 0)
    except (TypeError, ValueError):
        return 0


def _delta(run: CustodianRun) -> dict[str, int]:
    delta = (run.summary or {}).get("delta") or {}
    if not isinstance(delta, dict):
        return {"new": 0, "resolved": 0}
    return {
        "new": int(delta.get("new_count") or 0),
        "resolved": int(delta.get("gone_count") or 0),
    }


def governance_score(policies: int, policies_matched: int) -> float | None:
    """Share of policies with no matched resources (higher is better)."""
    if policies == 0:
        return None
    return round(100.0 * (policies - policies_matched) / policies, 1)


def assemble(tenant_id: str, filters: ReportFilters) -> ReportData:
    """Assemble the Cloud Governance report.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters (``severity_floor`` does not apply).

    Returns:
        ``ReportData`` with per-policy and per-provider results.
    """
    data = ReportData(
        report_type=GOVERNANCE,
        title="Cloud Governance Report",
        generated_at=timezone.now(),
        filters=filters,
    )
    runs = latest_runs(tenant_id, filters)
    if not runs:
        data.empty_state = EMPTY_STATE
        data.headline = EMPTY_STATE
        return data

    policy_rows: list[dict[str, Any]] = []
    resource_rows: list[dict[str, Any]] = []
    providers: dict[str, dict[str, Any]] = {}
    for run in runs:
        count = _resource_count(run)
        delta = _delta(run)
        label = provider_label(run.provider)
        policy_rows.append(
            {
                "policy": run.policy.name,
                "provider": label,
                "provider_type": run.provider.provider,
                "resources": count,
                "new": delta["new"],
                "resolved": delta["resolved"],
                "finished_at": run.finished_at.isoformat() if run.finished_at else "",
            }
        )
        bucket = providers.setdefault(
            str(run.provider_id),
            {
                "provider_id": str(run.provider_id),
                "provider": label,
                "provider_type": run.provider.provider,
                "policies": 0,
                "policies_matched": 0,
                "resources": 0,
            },
        )
        bucket["policies"] += 1
        bucket["resources"] += count
        if count:
            bucket["policies_matched"] += 1
        for item in (run.summary or {}).get("resources_preview") or []:
            if isinstance(item, dict):
                resource_rows.append(
                    {
                        "policy": run.policy.name,
                        "provider": label,
                        "uid": str(item.get("uid") or ""),
                        "name": str(item.get("name") or ""),
                        "type": str(item.get("type") or ""),
                        "region": str(item.get("region") or ""),
                    }
                )

    total_resources = sum(row["resources"] for row in policy_rows)
    matched = sum(1 for row in policy_rows if row["resources"])
    new = sum(row["new"] for row in policy_rows)
    resolved = sum(row["resolved"] for row in policy_rows)
    data.score = governance_score(len(policy_rows), matched)
    data.grade = grade_for(data.score)
    data.status_totals = {
        "pass": len(policy_rows) - matched,
        "fail": matched,
        "muted": 0,
        "manual": 0,
    }
    data.kpis = {
        "policies_evaluated": len(policy_rows),
        "policies_with_matches": matched,
        "matched_resources": total_resources,
        "new_since_last_run": new,
        "resolved_since_last_run": resolved,
    }
    data.headline = (
        f"{matched} of {len(policy_rows)} governance policies flag "
        f"{total_resources} resource(s); {new} new and {resolved} resolved since "
        f"the previous runs. Grade {data.grade}."
    )
    data.sources = sorted(providers.values(), key=lambda item: -item["resources"])
    data.top_risks = [
        {
            "check_id": row["policy"],
            "title": row["policy"],
            "severity": "medium",
            "findings": row["resources"],
            "resources": row["resources"],
            "service": row["provider_type"],
            "impact": (
                "Resources that drift from the organization's governance policy "
                "add cost or risk until they are brought back in line."
            ),
            "remediation": (
                f"Review the {row['resources']} resource(s) matched by "
                f"'{row['policy']}' and remediate or document an exception."
            ),
        }
        for row in policy_rows
        if row["resources"]
    ][:10]
    data.remediation = [
        {
            "priority": index,
            "action": risk["remediation"],
            "check_id": risk["check_id"],
            "title": risk["title"],
            "severity": risk["severity"],
            "resources": risk["resources"],
        }
        for index, risk in enumerate(data.top_risks, start=1)
    ]
    data.tables = [
        ReportTable(
            key="policies",
            title="Policies",
            columns=POLICY_COLUMNS,
            rows=policy_rows,
            total=len(policy_rows),
        ),
        ReportTable(
            key="resources",
            title="Matched resources (preview per policy)",
            columns=RESOURCE_COLUMNS,
            rows=resource_rows,
            total=len(resource_rows),
        ),
    ]
    return data
