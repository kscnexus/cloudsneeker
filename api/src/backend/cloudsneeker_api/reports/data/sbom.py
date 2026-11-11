"""Software bill of materials (SBOM) report data.

Reads the newest ``AppSecSbom`` of each target in scope (newest version
created inside the report's date window, when one is set) and the components
of those inventories (``AppSecComponent``).
"""

from __future__ import annotations

from typing import Any

from cloudsneeker_api.appsec.queries import visible_targets
from cloudsneeker_api.models_appsec import AppSecComponent, AppSecSbom
from cloudsneeker_api.reports.catalog import SBOM
from cloudsneeker_api.reports.data.common import max_detail_rows
from cloudsneeker_api.reports.schema import (
    SEVERITY_ORDER,
    ReportData,
    ReportFilters,
    ReportTable,
)
from django.db.models import Case, IntegerField, QuerySet, Value, When
from django.utils import timezone

TOP_COMPONENTS = 50

EMPTY_STATE = (
    "No software inventories in scope. Scan a repository, filesystem, or image "
    "target, or import an SBOM, in Application Security to populate this report."
)

INVENTORY_COLUMNS: list[tuple[str, str]] = [
    ("target", "Target"),
    ("mode", "Type"),
    ("format", "Format"),
    ("version", "Version"),
    ("component_count", "Components"),
    ("vulnerable_component_count", "Vulnerable components"),
    ("vulnerability_count", "Vulnerabilities"),
    ("ecosystems", "Ecosystems"),
    ("generated_at", "Generated"),
]

COMPONENT_COLUMNS: list[tuple[str, str]] = [
    ("max_severity", "Highest severity"),
    ("name", "Component"),
    ("version", "Version"),
    ("ecosystem", "Ecosystem"),
    ("target", "Target"),
    ("vulnerability_count", "Vulnerabilities"),
    ("fixed_version", "Fixed version"),
]

ECOSYSTEM_COLUMNS: list[tuple[str, str]] = [
    ("ecosystem", "Ecosystem"),
    ("components", "Components"),
    ("targets", "Targets"),
]


def latest_sboms(tenant_id: str, filters: ReportFilters) -> list[AppSecSbom]:
    """Newest SBOM of each target in scope.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters (providers; the date window bounds when the
            inventory was created).

    Returns:
        SBOMs with their target loaded, ordered by target name.
    """
    targets = visible_targets(tenant_id, set(filters.provider_ids) or None)
    queryset = AppSecSbom.objects.filter(
        tenant_id=tenant_id, target_id__in=targets.values("id")
    )
    if filters.date_from:
        queryset = queryset.filter(inserted_at__gte=filters.date_from)
    if filters.date_to:
        queryset = queryset.filter(inserted_at__lte=filters.date_to)
    sboms = list(
        queryset.select_related("target")
        .order_by("target_id", "-version")
        .distinct("target_id")
    )
    return sorted(sboms, key=lambda sbom: sbom.target.name)


def component_severity_rank() -> Case:
    """ORDER BY expression on ``max_severity``: critical first, empty last."""
    return Case(
        *[
            When(max_severity=severity, then=Value(index))
            for index, severity in enumerate(SEVERITY_ORDER)
        ],
        default=Value(len(SEVERITY_ORDER)),
        output_field=IntegerField(),
    )


def components_of(tenant_id: str, sboms: list[AppSecSbom]) -> QuerySet:
    """Components of the given inventories."""
    return AppSecComponent.objects.filter(
        tenant_id=tenant_id, sbom_id__in=[sbom.id for sbom in sboms]
    )


def _ecosystems(summary: Any) -> dict[str, int]:
    ecosystems = (
        (summary or {}).get("ecosystems") if isinstance(summary, dict) else None
    )
    if not isinstance(ecosystems, dict):
        return {}
    result = {}
    for name, count in ecosystems.items():
        try:
            result[str(name)] = int(count or 0)
        except (TypeError, ValueError):
            continue
    return result


def assemble(tenant_id: str, filters: ReportFilters) -> ReportData:
    """Assemble the SBOM report.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters (providers, date window; the severity floor
            limits the vulnerable components listed).

    Returns:
        ``ReportData`` with one inventory row per target, the most vulnerable
        components and the ecosystem mix. There is no grade.
    """
    data = ReportData(
        report_type=SBOM,
        title="Software Bill of Materials Report",
        generated_at=timezone.now(),
        filters=filters,
    )
    sboms = latest_sboms(tenant_id, filters)
    if not sboms:
        data.empty_state = EMPTY_STATE
        data.headline = EMPTY_STATE
        return data

    inventory_rows = []
    ecosystem_totals: dict[str, dict[str, Any]] = {}
    for sbom in sboms:
        ecosystems = _ecosystems(sbom.summary)
        for name, count in ecosystems.items():
            bucket = ecosystem_totals.setdefault(
                name, {"ecosystem": name, "components": 0, "targets": 0}
            )
            bucket["components"] += count
            bucket["targets"] += 1
        inventory_rows.append(
            {
                "target": sbom.target.name,
                "mode": sbom.target.mode,
                "format": sbom.document_format or sbom.source,
                "version": sbom.version,
                "component_count": sbom.component_count,
                "vulnerable_component_count": sbom.vulnerable_component_count,
                "vulnerability_count": sbom.vulnerability_count,
                "ecosystems": ", ".join(
                    name
                    for name, _ in sorted(
                        ecosystems.items(), key=lambda item: -item[1]
                    )[:5]
                ),
                "generated_at": sbom.inserted_at.date().isoformat(),
            }
        )

    components = components_of(tenant_id, sboms)
    vulnerable = components.filter(vulnerability_count__gt=0)
    if filters.severity_floor:
        vulnerable = vulnerable.filter(max_severity__in=filters.severities())
    for severity in SEVERITY_ORDER:
        data.severity_totals[severity] = vulnerable.filter(
            max_severity=severity
        ).count()
    vulnerable_total = vulnerable.count()
    bound = min(TOP_COMPONENTS, max_detail_rows())
    component_rows = [
        {
            "max_severity": item["max_severity"] or "unknown",
            "name": item["name"],
            "version": item["version"],
            "ecosystem": item["ecosystem"],
            "target": item["target__name"],
            "vulnerability_count": item["vulnerability_count"],
            "fixed_version": item["fixed_version"],
        }
        for item in vulnerable.annotate(cs_rank=component_severity_rank())
        .order_by("cs_rank", "-vulnerability_count", "name")
        .values(
            "max_severity",
            "name",
            "version",
            "ecosystem",
            "target__name",
            "vulnerability_count",
            "fixed_version",
        )[:bound]
    ]

    total_components = sum(sbom.component_count for sbom in sboms)
    vulnerable_components = sum(sbom.vulnerable_component_count for sbom in sboms)
    vulnerabilities = sum(sbom.vulnerability_count for sbom in sboms)
    fixable = vulnerable.exclude(fixed_version="").count()
    data.kpis = {
        "targets_with_sbom": len(sboms),
        "components": total_components,
        "vulnerable_components": vulnerable_components,
        "vulnerabilities": vulnerabilities,
        "ecosystems": len(ecosystem_totals),
        "vulnerable_components_with_fix": fixable,
    }
    data.headline = (
        f"{len(sboms)} target inventory(ies) list {total_components} component(s); "
        f"{vulnerable_components} are vulnerable with {vulnerabilities} "
        f"vulnerability(ies) in total."
    )
    if fixable:
        data.remediation = [
            {
                "priority": 1,
                "action": (
                    f"Upgrade the {fixable} vulnerable component(s) that have a "
                    "fixed version, starting with the highest severity."
                ),
            }
        ]
    ecosystem_rows = sorted(
        ecosystem_totals.values(), key=lambda item: -item["components"]
    )
    data.tables = [
        ReportTable(
            key="inventories",
            title="Latest inventory per target",
            columns=INVENTORY_COLUMNS,
            rows=inventory_rows,
            total=len(inventory_rows),
        ),
        ReportTable(
            key="vulnerable_components",
            title="Most vulnerable components",
            columns=COMPONENT_COLUMNS,
            rows=component_rows,
            total=vulnerable_total,
            truncated=len(component_rows) < vulnerable_total,
        ),
        ReportTable(
            key="ecosystems",
            title="Ecosystems",
            columns=ECOSYSTEM_COLUMNS,
            rows=ecosystem_rows,
            total=len(ecosystem_rows),
        ),
    ]
    return data
