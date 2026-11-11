"""Software inventory storage: one SBOM row and its components per scan."""

from __future__ import annotations

from typing import Any

from cloudsneeker_api.appsec import parser, sbom
from cloudsneeker_api.appsec.parser import NormalizedComponent, NormalizedFinding

BATCH = 1000
DEFAULT_SBOM_VERSIONS_KEPT = 10


def _version_key(version: str) -> tuple:
    parts = []
    for chunk in str(version).replace("-", ".").replace("+", ".").split("."):
        parts.append((0, int(chunk), "") if chunk.isdigit() else (1, 0, chunk))
    return tuple(parts)


def highest_fix(versions: list[str]) -> str:
    """The version that satisfies every listed fix (the highest one).

    A fixed-version field may hold alternatives per release line
    (``"1.2.3, 2.0.1"``); the first is used, as the closest upgrade.
    """
    candidates = [
        item.split(",")[0].strip() for item in versions if item and item.strip()
    ]
    if not candidates:
        return ""
    return max(candidates, key=_version_key)


def vulnerability_index(
    findings: list[NormalizedFinding],
) -> dict[tuple[str, str], dict[str, Any]]:
    """Reported vulnerabilities by (location, package id or name@version)."""
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        if finding.category != parser.CATEGORY_VULNERABILITY or finding.suppressed:
            continue
        keys = {
            finding.details.get("pkg_id") or "",
            f"{finding.pkg_name}@{finding.pkg_version}",
        }
        for key in keys:
            if not key:
                continue
            entry = index.setdefault(
                (finding.location, key), {"ids": set(), "severities": [], "fixes": []}
            )
            if finding.rule_id not in entry["ids"]:
                entry["ids"].add(finding.rule_id)
                entry["severities"].append(finding.severity)
                if finding.fixed_version:
                    entry["fixes"].append(finding.fixed_version)
    return index


def component_rows(
    components: list[NormalizedComponent], findings: list[NormalizedFinding]
) -> list[dict[str, Any]]:
    """Component field dicts with per-component vulnerability counts.

    Duplicate entries (same package listed twice in one location) collapse.
    """
    index = vulnerability_index(findings)
    rows = []
    seen: set[tuple[str, str, str, str]] = set()
    for component in components:
        identity = (
            component.location,
            component.ref,
            component.name,
            component.version,
        )
        if identity in seen:
            continue
        seen.add(identity)
        entry = index.get((component.location, component.ref)) or index.get(
            (component.location, f"{component.name}@{component.version}")
        )
        rows.append(
            {
                "ref": component.ref,
                "name": component.name,
                "version": component.version,
                "ecosystem": component.ecosystem,
                "package_class": component.package_class,
                "purl": component.purl,
                "licenses": component.licenses,
                "relationship": component.relationship,
                "dev": component.dev,
                "location": component.location,
                "depends_on": component.depends_on,
                "vulnerability_count": len(entry["ids"]) if entry else 0,
                "max_severity": sbom.max_severity(entry["severities"]) if entry else "",
                "fixed_version": highest_fix(entry["fixes"])[:200] if entry else "",
            }
        )
    return rows


def store_inventory(
    *,
    tenant_id: str,
    target,
    run,
    components: list[NormalizedComponent],
    findings: list[NormalizedFinding],
    artifact_name: str,
    artifact_type: str,
    source: str,
    document_format: str = "",
    keep_versions: int = DEFAULT_SBOM_VERSIONS_KEPT,
    using: str | None = None,
):
    """Store the components of a scan as the target's next SBOM version.

    Args:
        tenant_id: Tenant of the target.
        target: ``TrivyTarget``.
        run: ``TrivyRun``.
        components: Parser output.
        findings: Findings of the same scan, for per-component counts.
        artifact_name: Scanned artifact (repository, image, file).
        artifact_type: Artifact type reported by the engine.
        source: ``generated`` or ``imported``.
        document_format: Format of an imported document.
        keep_versions: Older versions beyond this count are deleted.
        using: Database alias.

    Returns:
        The ``AppSecSbom`` row, or ``None`` when the scan listed no package.
    """
    from cloudsneeker_api.models import AppSecComponent, AppSecSbom

    rows = component_rows(components, findings)
    if not rows:
        return None
    sboms = AppSecSbom.objects.using(using) if using else AppSecSbom.objects
    manager = AppSecComponent.objects.using(using) if using else AppSecComponent.objects
    latest = (
        sboms.filter(tenant_id=tenant_id, target=target)
        .order_by("-version")
        .values_list("version", flat=True)
        .first()
    )
    record = sboms.create(
        tenant_id=tenant_id,
        target=target,
        run=run,
        source=source,
        document_format=document_format,
        version=(latest or 0) + 1,
        artifact_name=artifact_name[:600],
        artifact_type=artifact_type[:64],
        component_count=len(rows),
        vulnerable_component_count=sum(1 for row in rows if row["vulnerability_count"]),
        vulnerability_count=sum(row["vulnerability_count"] for row in rows),
        summary=sbom.summarize(rows),
    )
    for start in range(0, len(rows), BATCH):
        manager.bulk_create(
            [
                AppSecComponent(tenant_id=tenant_id, sbom=record, target=target, **row)
                for row in rows[start : start + BATCH]
            ]
        )

    if keep_versions > 0:
        stale = list(
            sboms.filter(tenant_id=tenant_id, target=target)
            .order_by("-version")
            .values_list("id", flat=True)[keep_versions:]
        )
        if stale:
            sboms.filter(tenant_id=tenant_id, id__in=stale).delete()
    return record
