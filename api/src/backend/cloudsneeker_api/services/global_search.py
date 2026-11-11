"""Global search: one query across the three product areas.

Groups, each with a total and the first few hits:

* findings of Cloud Security, Application Security and Governance (the area
  findings read path, so latest scans, mutelist and visibility apply);
* cloud accounts (providers other than the code and image providers);
* Application Security targets and applications;
* Governance policies;
* alert rules.

Reads follow the role's provider visibility and the plan's product areas, the
same rules as each area's own list. Text matching is case-insensitive.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from api.models import Provider
from cloudsneeker_api.reports.access import visible_provider_ids
from cloudsneeker_api.services.area_findings import (
    AREA,
    AREA_FEATURE,
    AreaFindingQuery,
    list_area_findings,
)
from django.db.models import Q

SEARCH_MIN_LENGTH = 2
SEARCH_MAX_LENGTH = 200
HITS_PER_GROUP = 5

# Providers that hold Application Security targets, not cloud accounts.
APPLICATION_PROVIDER_TYPES = ("iac", "image")

GROUP = {
    "CLOUD_FINDINGS": "cloud_findings",
    "APPLICATION_FINDINGS": "application_security_findings",
    "GOVERNANCE_FINDINGS": "governance_findings",
    "ACCOUNTS": "cloud_accounts",
    "TARGETS": "application_targets",
    "APPLICATIONS": "applications",
    "POLICIES": "governance_policies",
    "ALERT_RULES": "alert_rules",
}

FINDING_GROUPS = (
    (AREA.CLOUD, GROUP["CLOUD_FINDINGS"]),
    (AREA.APPLICATION_SECURITY, GROUP["APPLICATION_FINDINGS"]),
    (AREA.GOVERNANCE, GROUP["GOVERNANCE_FINDINGS"]),
)


class GlobalSearchError(ValueError):
    """The query is too short or too long."""


@dataclass
class SearchHit:
    id: str
    title: str
    subtitle: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class SearchGroup:
    kind: str
    count: int
    hits: list[SearchHit]


def clean_query(raw: Any) -> str:
    text = " ".join(str(raw or "").split())
    if len(text) < SEARCH_MIN_LENGTH:
        raise GlobalSearchError(f"Search for at least {SEARCH_MIN_LENGTH} characters.")
    return text[:SEARCH_MAX_LENGTH]


def _visible(queryset, visible: set[str] | None, field_name: str = "provider_id"):
    if visible is None:
        return queryset
    return queryset.filter(**{f"{field_name}__in": list(visible)})


def _group(kind: str, queryset, to_hit) -> SearchGroup:
    return SearchGroup(
        kind=kind,
        count=queryset.count(),
        hits=[to_hit(row) for row in queryset[:HITS_PER_GROUP]],
    )


def _finding_group(tenant_id: str, role, area: str, kind: str, text: str):
    page = list_area_findings(
        tenant_id,
        role,
        AreaFindingQuery(area=area, search=text, page_size=HITS_PER_GROUP),
    )
    return SearchGroup(
        kind=kind,
        count=page.count,
        hits=[
            SearchHit(
                id=row["uid"],
                title=row.get("title") or row.get("check_id") or row["uid"],
                subtitle=row.get("source_name") or "",
                attributes={
                    "area": area,
                    "severity": row.get("severity") or "",
                    "check_id": row.get("check_id") or "",
                    "finding_id": row.get("finding_id"),
                    "muted": bool(row.get("muted")),
                },
            )
            for row in page.rows
        ],
    )


def search(tenant_id: str, role, plan, text: str) -> list[SearchGroup]:
    """Every group the role and plan allow, in a fixed order."""
    from cloudsneeker_api.models import AlertRule, CustodianPolicy, TrivyTarget
    from cloudsneeker_api.models_appsec import AppSecApplication

    visible = visible_provider_ids(role) if role is not None else None
    allowed = {
        area for area, feature in AREA_FEATURE.items() if plan.has_feature(feature)
    }
    groups: list[SearchGroup] = []

    for area, kind in FINDING_GROUPS:
        if area in allowed:
            groups.append(_finding_group(tenant_id, role, area, kind, text))

    if AREA.CLOUD in allowed:
        accounts = _visible(
            Provider.objects.filter(tenant_id=tenant_id)
            .exclude(provider__in=APPLICATION_PROVIDER_TYPES)
            .filter(Q(alias__icontains=text) | Q(uid__icontains=text))
            .order_by("alias", "uid"),
            visible,
            "id",
        )
        groups.append(
            _group(
                GROUP["ACCOUNTS"],
                accounts,
                lambda row: SearchHit(
                    id=str(row.id),
                    title=row.alias or row.uid,
                    subtitle=row.uid if row.alias else "",
                    attributes={"provider": row.provider, "uid": row.uid},
                ),
            )
        )

    if AREA.APPLICATION_SECURITY in allowed:
        targets = _visible(
            TrivyTarget.objects.filter(tenant_id=tenant_id)
            .filter(Q(name__icontains=text) | Q(description__icontains=text))
            .order_by("name"),
            visible,
        )
        groups.append(
            _group(
                GROUP["TARGETS"],
                targets,
                lambda row: SearchHit(
                    id=str(row.id),
                    title=row.name,
                    subtitle=row.get_mode_display(),
                    attributes={"mode": row.mode},
                ),
            )
        )
        applications = (
            AppSecApplication.objects.filter(tenant_id=tenant_id)
            .filter(
                Q(name__icontains=text)
                | Q(description__icontains=text)
                | Q(owner__icontains=text)
            )
            .order_by("name")
        )
        groups.append(
            _group(
                GROUP["APPLICATIONS"],
                applications,
                lambda row: SearchHit(
                    id=str(row.id),
                    title=row.name,
                    subtitle=row.owner or "",
                ),
            )
        )

    if AREA.GOVERNANCE in allowed:
        policies = _visible(
            CustodianPolicy.objects.filter(tenant_id=tenant_id)
            .filter(Q(name__icontains=text) | Q(description__icontains=text))
            .order_by("name"),
            visible,
        )
        groups.append(
            _group(
                GROUP["POLICIES"],
                policies,
                lambda row: SearchHit(
                    id=str(row.id),
                    title=row.name,
                    subtitle=row.description[:120] if row.description else "",
                ),
            )
        )

    rules = (
        AlertRule.objects.filter(tenant_id=tenant_id)
        .filter(Q(name__icontains=text) | Q(description__icontains=text))
        .order_by("name")
    )
    groups.append(
        _group(
            GROUP["ALERT_RULES"],
            rules,
            lambda row: SearchHit(
                id=str(row.id),
                title=row.name,
                subtitle="Enabled" if row.enabled else "Paused",
            ),
        )
    )
    return groups
