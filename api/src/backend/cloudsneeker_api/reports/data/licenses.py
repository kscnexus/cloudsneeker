"""License report data.

* Licenses in use come from the components of the newest SBOM of each target
  (``AppSecComponent.licenses``), the same inventories the SBOM report reads.
* License categories come from license findings (``details.license_category``)
  and, when present, the SBOM summary (``summary.license_categories``).
* Policy violations are open, unsuppressed ``AppSecFinding`` rows of category
  ``license``: the scanner flags a license when the tenant's license policy
  (or the scanner default) classifies it as restricted or forbidden.
"""

from __future__ import annotations

from typing import Any

from cloudsneeker_api.appsec.queries import ACTIVE_STATES, findings_queryset
from cloudsneeker_api.models_appsec import AppSecFinding
from cloudsneeker_api.reports.catalog import LICENSES
from cloudsneeker_api.reports.data.common import max_detail_rows
from cloudsneeker_api.reports.data.sbom import components_of, latest_sboms
from cloudsneeker_api.reports.schema import (
    SEVERITY_ORDER,
    ReportData,
    ReportFilters,
    ReportTable,
)
from django.utils import timezone

NO_LICENSE = "(no license declared)"

EMPTY_STATE = (
    "No license data in scope. Scan a repository, filesystem, or image target "
    "with license scanning enabled in Application Security to populate this "
    "report."
)

LICENSE_COLUMNS: list[tuple[str, str]] = [
    ("license", "License"),
    ("category", "Category"),
    ("components", "Components"),
    ("targets", "Targets"),
    ("violations", "Policy violations"),
]

VIOLATION_COLUMNS: list[tuple[str, str]] = [
    ("severity", "Severity"),
    ("license", "License"),
    ("category", "Category"),
    ("package", "Package"),
    ("target", "Target"),
    ("location", "Location"),
    ("state", "State"),
    ("triage_status", "Triage"),
]

CATEGORY_COLUMNS: list[tuple[str, str]] = [
    ("category", "Category"),
    ("count", "Count"),
]


def _summary_categories(summary: Any) -> dict[str, int]:
    """``summary.license_categories`` as ``{category: count}`` when present."""
    categories = (
        summary.get("license_categories") if isinstance(summary, dict) else None
    )
    if not isinstance(categories, dict):
        return {}
    result = {}
    for name, count in categories.items():
        try:
            result[str(name)] = int(count or 0)
        except (TypeError, ValueError):
            continue
    return result


def license_usage(
    tenant_id: str, sboms: list
) -> tuple[dict[str, dict[str, Any]], int, int]:
    """Components and targets per license across the given inventories.

    Returns:
        ``(usage, components, without_license)`` where ``usage`` maps a
        license name to ``{"components": int, "targets": set}``.
    """
    usage: dict[str, dict[str, Any]] = {}
    components = 0
    without_license = 0
    rows = components_of(tenant_id, sboms).values_list("licenses", "target_id")
    for licenses, target_id in rows.iterator(chunk_size=5000):
        components += 1
        names = (
            [str(item) for item in licenses or [] if item]
            if isinstance(licenses, list)
            else []
        )
        if not names:
            without_license += 1
            names = [NO_LICENSE]
        for name in set(names):
            entry = usage.setdefault(name, {"components": 0, "targets": set()})
            entry["components"] += 1
            entry["targets"].add(str(target_id))
    return usage, components, without_license


def assemble(tenant_id: str, filters: ReportFilters) -> ReportData:
    """Assemble the license report.

    Args:
        tenant_id: Tenant UUID string.
        filters: Report filters (providers, date window on inventories; the
            severity floor limits the violations listed).

    Returns:
        ``ReportData`` with licenses in use, categories and policy
        violations. There is no grade.
    """
    data = ReportData(
        report_type=LICENSES,
        title="License Report",
        generated_at=timezone.now(),
        filters=filters,
    )
    sboms = latest_sboms(tenant_id, filters)
    findings = findings_queryset(tenant_id, set(filters.provider_ids) or None).filter(
        category=AppSecFinding.Category.LICENSE
    )
    violations = findings.filter(state__in=ACTIVE_STATES, suppressed=False)
    if filters.severity_floor:
        violations = violations.filter(severity__in=filters.severities())
    usage, component_total, without_license = license_usage(tenant_id, sboms)
    if not usage and not findings.exists():
        data.empty_state = EMPTY_STATE
        data.headline = EMPTY_STATE
        return data

    category_of: dict[str, str] = {}
    for name, category in (
        findings.order_by()
        .values_list("rule_id", "details__license_category")
        .distinct()
    ):
        if name and category and name not in category_of:
            category_of[name] = str(category)

    violations_by_license: dict[str, int] = {}
    for name in violations.values_list("rule_id", flat=True):
        violations_by_license[name] = violations_by_license.get(name, 0) + 1

    for severity in SEVERITY_ORDER:
        data.severity_totals[severity] = violations.filter(severity=severity).count()

    license_rows = []
    for name in set(usage) | set(violations_by_license):
        entry = usage.get(name, {"components": 0, "targets": set()})
        license_rows.append(
            {
                "license": name,
                "category": category_of.get(name, ""),
                "components": entry["components"],
                "targets": len(entry["targets"]),
                "violations": violations_by_license.get(name, 0),
            }
        )
    license_rows.sort(
        key=lambda row: (-row["violations"], -row["components"], row["license"])
    )

    violation_total = violations.count()
    bound = max_detail_rows()
    violation_rows = [
        {
            "severity": item["severity"],
            "license": item["rule_id"],
            "category": str(item["details__license_category"] or ""),
            "package": item["pkg_name"],
            "target": item["target__name"],
            "location": item["file_path"] or item["location"],
            "state": item["state"],
            "triage_status": item["triage_status"],
        }
        for item in violations.order_by("-severity_rank", "rule_id", "pkg_name").values(
            "severity",
            "rule_id",
            "details__license_category",
            "pkg_name",
            "target__name",
            "file_path",
            "location",
            "state",
            "triage_status",
        )[:bound]
    ]

    categories: dict[str, int] = {}
    for sbom in sboms:
        for name, count in _summary_categories(sbom.summary).items():
            categories[name] = categories.get(name, 0) + count
    if not categories:
        for row in license_rows:
            if row["category"]:
                categories[row["category"]] = (
                    categories.get(row["category"], 0) + row["components"]
                )
    category_rows = [
        {"category": name, "count": count}
        for name, count in sorted(categories.items(), key=lambda item: -item[1])
    ]

    distinct = len([name for name in usage if name != NO_LICENSE])
    licensed_targets = len(
        {target for entry in usage.values() for target in entry["targets"]}
    )
    data.kpis = {
        "licenses_in_use": distinct,
        "components": component_total,
        "components_without_license": without_license,
        "targets": licensed_targets,
        "policy_violations": violation_total,
        "licenses_with_violations": len(violations_by_license),
    }
    data.headline = (
        f"{distinct} license(s) across {component_total} component(s) in "
        f"{licensed_targets} target(s); {violation_total} license policy "
        f"violation(s) open."
    )
    actions = []
    if violation_total:
        worst = license_rows[0]["license"] if license_rows else ""
        actions.append(
            f"Replace or get legal approval for components under restricted "
            f"licenses ({violation_total} open violation(s), most under {worst})."
        )
    if without_license:
        actions.append(
            f"Identify the license of {without_license} component(s) that declare none."
        )
    data.remediation = [
        {"priority": index, "action": action}
        for index, action in enumerate(actions, start=1)
    ]
    data.tables = [
        ReportTable(
            key="licenses",
            title="Licenses in use",
            columns=LICENSE_COLUMNS,
            rows=license_rows[:bound],
            total=len(license_rows),
            truncated=len(license_rows) > bound,
        ),
        ReportTable(
            key="violations",
            title="License policy violations",
            columns=VIOLATION_COLUMNS,
            rows=violation_rows,
            total=violation_total,
            truncated=len(violation_rows) < violation_total,
        ),
        ReportTable(
            key="categories",
            title="License categories",
            columns=CATEGORY_COLUMNS,
            rows=category_rows,
            total=len(category_rows),
        ),
    ]
    return data
