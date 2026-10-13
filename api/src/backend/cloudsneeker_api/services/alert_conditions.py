"""Evaluate alert-rule condition DSL against Finding querysets."""

from __future__ import annotations

from typing import Any

from api.models import Finding
from django.db.models import QuerySet

BOOLEAN_OPS = {"and", "or", "not"}
AGGREGATE_OPS = {"count_gte", "count_lte", "any", "none"}

FILTER_FIELD_MAP = {
    "severity": "severity",
    "delta": "delta",
    "check_id": "check_id",
    "finding_group_id": "check_id",
    "categories": "categories__contains",
    "resource_regions": "resource_regions__overlap",
    "resource_services": "resource_services__overlap",
    "resource_types": "resource_types__overlap",
    "resource_uid": "uid",
    "resource_groups": "resource_groups",
    "provider_id": "scan__provider_id",
    "provider_type": "scan__provider__provider",
}


def apply_leaf_filter(queryset: QuerySet[Finding], leaf: dict[str, Any]) -> QuerySet[Finding]:
    """Apply a leaf filter mapping to a Finding queryset."""
    for field, value in leaf.items():
        mapped = FILTER_FIELD_MAP.get(field)
        if not mapped or value in (None, [], ""):
            continue
        if mapped.endswith("__contains") and isinstance(value, list):
            for item in value:
                queryset = queryset.filter(**{mapped: [item]})
            continue
        if mapped.endswith("__overlap") and isinstance(value, list):
            queryset = queryset.filter(**{mapped: value})
            continue
        if isinstance(value, list):
            queryset = queryset.filter(**{f"{mapped}__in": value})
        else:
            queryset = queryset.filter(**{mapped: value})
    return queryset


def evaluate_condition(
    queryset: QuerySet[Finding], condition: dict[str, Any]
) -> tuple[bool, QuerySet[Finding]]:
    """Return whether the condition matches and the matching finding queryset."""
    op = condition.get("op")
    if op == "and":
        matched = queryset
        for child in condition.get("children", []):
            ok, matched = evaluate_condition(matched, child)
            if not ok:
                return False, Finding.objects.none()
        return matched.exists(), matched
    if op == "or":
        ids: set = set()
        for child in condition.get("children", []):
            ok, matched = evaluate_condition(queryset, child)
            if ok:
                ids.update(matched.values_list("id", flat=True))
        matched = queryset.filter(id__in=ids) if ids else Finding.objects.none()
        return matched.exists(), matched
    if op == "not":
        child = condition.get("child") or {}
        ok, matched = evaluate_condition(queryset, child)
        remaining = queryset.exclude(id__in=matched.values_list("id", flat=True))
        return remaining.exists(), remaining

    leaf = condition.get("filter") or {}
    filtered = apply_leaf_filter(queryset, leaf)
    if op == "count_gte":
        value = int(condition.get("value", 0))
        return filtered.count() >= value, filtered
    if op == "count_lte":
        value = int(condition.get("value", 0))
        return filtered.count() <= value, filtered
    if op == "any":
        return filtered.exists(), filtered
    if op == "none":
        return not filtered.exists(), Finding.objects.none()

    return False, Finding.objects.none()


def preview_condition(
    queryset: QuerySet[Finding], condition: dict[str, Any]
) -> dict[str, Any]:
    """Build the preview summary the Alerts UI expects."""
    try:
        _matched, findings = evaluate_condition(queryset, condition)
        findings = findings[:50]
        counts: dict[str, int] = {}
        for severity in findings.values_list("severity", flat=True):
            key = str(severity)
            counts[key] = counts.get(key, 0) + 1
        sample_ids = [str(item) for item in findings.values_list("id", flat=True)[:10]]
        top_severity = max(counts, key=counts.get) if counts else None
        return {
            "summary": {
                "finding_count_total": sum(counts.values()),
                "counts_by_severity": counts,
                "top_severity": top_severity,
                "top_findings": sample_ids,
            },
            "sample_finding_ids": sample_ids,
            "evaluation_failed": False,
            "last_error": None,
            "summary_fallback": False,
        }
    except Exception as exc:  # noqa: BLE001 - preview must never 500 the form
        return {
            "summary": {},
            "sample_finding_ids": [],
            "evaluation_failed": True,
            "last_error": str(exc),
            "summary_fallback": True,
        }
