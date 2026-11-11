"""Software inventory helpers: summary, version comparison, CycloneDX export.

Components are plain dicts with the ``AppSecComponent`` field names, so the
same functions serve parsed reports and database rows.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import datetime
from typing import Any

CYCLONEDX_SPEC_VERSION = "1.6"
SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "unknown": 0,
}


def component_key(component: dict[str, Any]) -> str:
    """Identity of a package across inventories, without its version."""
    return "|".join(
        (
            str(component.get("ecosystem") or ""),
            str(component.get("name") or ""),
            str(component.get("location") or ""),
        )
    )


def detect_document_format(document: Any) -> str:
    """Return ``cyclonedx``, ``spdx`` or an empty string for an SBOM payload.

    Args:
        document: Parsed JSON object, or raw text (SPDX tag-value).
    """
    if isinstance(document, dict):
        if str(document.get("bomFormat") or "").lower() == "cyclonedx":
            return "cyclonedx"
        if "spdxVersion" in document or "SPDXID" in document:
            return "spdx"
        return ""
    if isinstance(document, str) and "SPDXVersion:" in document[:2000]:
        return "spdx"
    return ""


def summarize(components: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Count components by ecosystem, license and relationship."""
    ecosystems: dict[str, int] = {}
    licenses: dict[str, int] = {}
    relationships: dict[str, int] = {}
    without_license = 0
    total = 0
    for component in components:
        total += 1
        ecosystem = str(component.get("ecosystem") or "unknown")
        ecosystems[ecosystem] = ecosystems.get(ecosystem, 0) + 1
        relationship = str(component.get("relationship") or "unknown")
        relationships[relationship] = relationships.get(relationship, 0) + 1
        names = [str(item) for item in component.get("licenses") or [] if item]
        if not names:
            without_license += 1
        for name in names:
            licenses[name] = licenses.get(name, 0) + 1
    return {
        "total": total,
        "ecosystems": dict(sorted(ecosystems.items(), key=lambda item: -item[1])),
        "licenses": dict(sorted(licenses.items(), key=lambda item: -item[1])[:50]),
        "relationships": relationships,
        "without_license": without_license,
    }


def diff_components(
    base: Iterable[dict[str, Any]], head: Iterable[dict[str, Any]]
) -> dict[str, Any]:
    """Compare two inventories of the same target.

    Args:
        base: Components of the older inventory.
        head: Components of the newer inventory.

    Returns:
        ``added``, ``removed`` and ``changed`` (version differs) lists plus
        ``unchanged`` count. A package present at several versions is
        compared as a set of versions.
    """

    def index(items: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        table: dict[str, dict[str, Any]] = {}
        for item in items:
            entry = table.setdefault(
                component_key(item),
                {
                    "name": item.get("name") or "",
                    "ecosystem": item.get("ecosystem") or "",
                    "location": item.get("location") or "",
                    "purl": item.get("purl") or "",
                    "versions": set(),
                    "licenses": set(),
                },
            )
            entry["versions"].add(str(item.get("version") or ""))
            entry["licenses"].update(str(x) for x in item.get("licenses") or [])
        return table

    base_index = index(base)
    head_index = index(head)

    def row(entry: dict[str, Any], **extra: Any) -> dict[str, Any]:
        return {
            "name": entry["name"],
            "ecosystem": entry["ecosystem"],
            "location": entry["location"],
            "purl": entry["purl"],
            "licenses": sorted(entry["licenses"]),
            **extra,
        }

    added, removed, changed = [], [], []
    unchanged = 0
    for key, entry in head_index.items():
        previous = base_index.get(key)
        if previous is None:
            added.append(row(entry, versions=sorted(entry["versions"])))
        elif previous["versions"] != entry["versions"]:
            changed.append(
                row(
                    entry,
                    from_versions=sorted(previous["versions"]),
                    to_versions=sorted(entry["versions"]),
                )
            )
        else:
            unchanged += 1
    for key, entry in base_index.items():
        if key not in head_index:
            removed.append(row(entry, versions=sorted(entry["versions"])))

    def by_name(item: dict[str, Any]) -> tuple[str, str]:
        return (str(item["name"]).lower(), str(item["location"]))

    return {
        "added": sorted(added, key=by_name),
        "removed": sorted(removed, key=by_name),
        "changed": sorted(changed, key=by_name),
        "unchanged": unchanged,
    }


def max_severity(severities: Iterable[str]) -> str:
    """Highest severity in the product scale, or an empty string."""
    best = ""
    for severity in severities:
        if not best or SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(best, 0):
            best = severity
    return best


def build_cyclonedx(
    components: Iterable[dict[str, Any]],
    *,
    name: str,
    created_at: datetime,
    tool_name: str,
    tool_version: str = "",
) -> dict[str, Any]:
    """Build a CycloneDX JSON document from stored components.

    Used when the scan report is no longer on disk for the engine to
    convert. It lists components and their dependency edges; it carries no
    vulnerabilities.

    Args:
        components: Component dicts.
        name: Name of the scanned artifact.
        created_at: Timestamp of the inventory.
        tool_name: Product name recorded as the generating tool.
        tool_version: Engine version that produced the inventory.

    Returns:
        A CycloneDX 1.6 document.
    """
    items = list(components)
    refs: dict[str, str] = {}
    cdx_components = []
    for index, component in enumerate(items):
        bom_ref = str(
            component.get("purl")
            or component.get("ref")
            or f"{component.get('name')}@{component.get('version')}"
        )
        if bom_ref in refs.values():
            bom_ref = f"{bom_ref}#{index}"
        if component.get("ref"):
            refs[str(component["ref"])] = bom_ref
        entry: dict[str, Any] = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": component.get("name") or "",
        }
        if component.get("version"):
            entry["version"] = component["version"]
        if component.get("purl"):
            entry["purl"] = component["purl"]
        licenses = [str(item) for item in component.get("licenses") or [] if item]
        if licenses:
            entry["licenses"] = [{"license": {"name": item}} for item in licenses]
        properties = []
        for label, key in (
            ("ecosystem", "ecosystem"),
            ("location", "location"),
            ("relationship", "relationship"),
        ):
            if component.get(key):
                properties.append(
                    {"name": f"cloudsneeker:{label}", "value": str(component[key])}
                )
        if properties:
            entry["properties"] = properties
        cdx_components.append(entry)

    dependencies = []
    for component in items:
        source = refs.get(str(component.get("ref") or ""))
        targets = [
            refs[str(ref)]
            for ref in component.get("depends_on") or []
            if str(ref) in refs
        ]
        if source and targets:
            dependencies.append({"ref": source, "dependsOn": sorted(set(targets))})

    tool: dict[str, Any] = {"type": "application", "name": tool_name}
    if tool_version:
        tool["version"] = tool_version
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": created_at.isoformat(),
            "tools": {"components": [tool]},
            "component": {"type": "application", "name": name, "bom-ref": "root"},
        },
        "components": cdx_components,
        "dependencies": dependencies,
    }
