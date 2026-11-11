"""Area-aware alert rule evaluation.

Alert rules are stored as a condition tree (``services/alert_conditions.py``).
This module decides which findings a rule sees and builds the notification:

* Only failing, unmuted findings can match. Passed checks and suppressed
  findings never raise an alert.
* A condition may restrict itself to product areas with the ``area`` leaf
  field (``cloud``, ``application_security``, ``governance``). A rule without
  an ``area`` covers the two ``Finding``-backed areas, as before.
* Cloud and Application Security findings are ``Finding`` rows. Governance
  findings are the resources matched by the latest Custodian dry run of each
  policy (``services/governance_findings.py``); they are evaluated in memory
  and only by rules that name the governance area.
* Every notification names the area of each match and links to the page in
  the area that produced it (the scan, the application scan run or the policy
  run), never to another area's page.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import quote, urlencode

from api.models import Finding, Scan, StateChoices, StatusChoices
from cloudsneeker_api.services.alert_conditions import (
    APP_SECURITY_SCAN_SOURCE,
    AREA_APPLICATION_SECURITY,
    AREA_CLOUD,
    AREA_GOVERNANCE,
    area_q,
    evaluate_condition,
)
from django.conf import settings
from django.db.models import F, Q, QuerySet
from django.db.models.fields.json import KeyTextTransform

AREAS = (AREA_CLOUD, AREA_APPLICATION_SECURITY, AREA_GOVERNANCE)
FINDING_AREAS = (AREA_CLOUD, AREA_APPLICATION_SECURITY)
AREA_LABELS = {
    AREA_CLOUD: "Cloud Security",
    AREA_APPLICATION_SECURITY: "Application Security",
    AREA_GOVERNANCE: "Cloud Governance",
}


# --- Condition inspection ----------------------------------------------------


def _leaves(condition: dict[str, Any]) -> Iterable[dict[str, Any]]:
    if not isinstance(condition, dict):
        return
    if "filter" in condition and isinstance(condition.get("filter"), dict):
        yield condition["filter"]
    for child in condition.get("children") or []:
        yield from _leaves(child)
    child = condition.get("child")
    if isinstance(child, dict):
        yield from _leaves(child)


def _as_list(value: Any) -> list[str]:
    if value in (None, "", []):
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item not in (None, "")]
    return [str(value)]


def condition_areas(condition: dict[str, Any]) -> set[str]:
    """Areas a rule covers.

    The union of every ``area`` value in the tree; without one, the
    ``Finding``-backed areas (the behaviour before areas existed).
    """
    named: set[str] = set()
    for leaf in _leaves(condition or {}):
        named.update(value for value in _as_list(leaf.get("area")) if value in AREAS)
    return named or set(FINDING_AREAS)


def finding_area(scanner_args: dict[str, Any] | None) -> str:
    source = (scanner_args or {}).get("source")
    return AREA_APPLICATION_SECURITY if source == APP_SECURITY_SCAN_SOURCE else AREA_CLOUD


# --- Finding querysets ---------------------------------------------------------


def alertable_findings(tenant_id: str) -> QuerySet[Finding]:
    """Failing, unmuted findings of the tenant."""
    return Finding.all_objects.filter(
        tenant_id=tenant_id, status=StatusChoices.FAIL, muted=False
    )


def latest_scan_ids(tenant_id: str) -> list[str]:
    """Latest completed scan per cloud provider and per application target.

    Daily evaluation looks at the current state, not every historical scan, so
    a finding seen in ten scans is counted once.
    """
    scans = Scan.all_objects.filter(
        tenant_id=tenant_id, state=StateChoices.COMPLETED
    ).annotate(cs_source=KeyTextTransform("source", "scanner_args"))
    cloud = (
        scans.filter(Q(cs_source__isnull=True) | ~Q(cs_source=APP_SECURITY_SCAN_SOURCE))
        .order_by("provider_id", F("completed_at").desc(nulls_last=True))
        .distinct("provider_id")
        .values_list("id", flat=True)
    )
    ids = [str(pk) for pk in cloud]

    from cloudsneeker_api.models import TrivyRun

    app = (
        TrivyRun.objects.filter(
            tenant_id=tenant_id,
            status=TrivyRun.Status.COMPLETED,
            scan_id__isnull=False,
        )
        .order_by("target_id", F("finished_at").desc(nulls_last=True))
        .distinct("target_id")
        .values_list("scan_id", flat=True)
    )
    ids.extend(str(pk) for pk in app)
    return ids


# --- Governance (in memory) ---------------------------------------------------


def _governance_leaf_matches(finding: Any, leaf: dict[str, Any], provider_type: str) -> bool:
    for name, raw in leaf.items():
        values = _as_list(raw)
        if not values:
            continue
        if name == "area":
            if AREA_GOVERNANCE not in values:
                return False
        elif name == "severity":
            if finding.severity not in values:
                return False
        elif name in ("check_id", "finding_group_id"):
            if not ({finding.policy_id, finding.rule_name, finding.policy_name} & set(values)):
                return False
        elif name == "provider_id":
            if finding.provider_id not in values:
                return False
        elif name == "provider_type":
            if provider_type not in values:
                return False
        elif name == "resource_types":
            if finding.resource_type not in values:
                return False
        elif name == "resource_regions":
            if finding.region not in values:
                return False
        elif name == "resource_uid":
            if finding.resource_id not in values and finding.uid not in values:
                return False
        elif name == "delta":
            is_new = finding.first_seen_at == finding.last_seen_at
            if "new" in values and not is_new:
                return False
        # Fields without a governance meaning (services, categories, groups)
        # do not narrow the match, like an unknown field on Finding rows.
    return True


def evaluate_governance_condition(
    findings: list[Any], condition: dict[str, Any], provider_types: dict[str, str]
) -> tuple[bool, list[Any]]:
    """Same operators as ``evaluate_condition`` over governance findings."""
    op = (condition or {}).get("op")
    if op == "and":
        matched = findings
        for child in condition.get("children", []):
            ok, matched = evaluate_governance_condition(matched, child, provider_types)
            if not ok:
                return False, []
        return bool(matched), matched
    if op == "or":
        uids: set[str] = set()
        for child in condition.get("children", []):
            ok, matched = evaluate_governance_condition(findings, child, provider_types)
            if ok:
                uids.update(item.uid for item in matched)
        result = [item for item in findings if item.uid in uids]
        return bool(result), result
    if op == "not":
        ok, matched = evaluate_governance_condition(
            findings, condition.get("child") or {}, provider_types
        )
        excluded = {item.uid for item in matched}
        remaining = [item for item in findings if item.uid not in excluded]
        return bool(remaining), remaining

    leaf = (condition or {}).get("filter") or {}
    filtered = [
        item
        for item in findings
        if _governance_leaf_matches(item, leaf, provider_types.get(item.provider_id, ""))
    ]
    if op == "count_gte":
        return len(filtered) >= int(condition.get("value", 0)), filtered
    if op == "count_lte":
        return len(filtered) <= int(condition.get("value", 0)), filtered
    if op == "any":
        return bool(filtered), filtered
    if op == "none":
        return not filtered, []
    return False, []


# --- Results and messages -------------------------------------------------------


@dataclass
class AreaMatch:
    area: str
    count: int
    severity_counts: dict[str, int] = field(default_factory=dict)
    links: list[str] = field(default_factory=list)


@dataclass
class RuleMatch:
    matched: bool
    areas: list[AreaMatch] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(item.count for item in self.areas)


def _ui(path: str) -> str:
    base = (getattr(settings, "UI_BASE_URL", "") or "").rstrip("/")
    return f"{base}{path}" if base else path


def cloud_findings_link(scan_ids: list[str]) -> str:
    params = {
        "filter[status__in]": "FAIL",
        "filter[muted]": "false",
    }
    if scan_ids:
        params["filter[scan__in]"] = ",".join(scan_ids)
    return _ui(f"/findings?{urlencode(params, safe='[],')}")


def app_security_run_link(target_id: str, run_id: str) -> str:
    return _ui(
        f"/application-security/{quote(str(target_id))}/runs/{quote(str(run_id))}"
    )


def governance_run_link(policy_id: str, run_id: str) -> str:
    return _ui(f"/governance/{quote(str(policy_id))}/runs/{quote(str(run_id))}")


def _severity_counts(values: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return counts


def evaluate_finding_rule(
    tenant_id: str, findings: QuerySet[Finding], condition: dict[str, Any]
) -> RuleMatch:
    """Evaluate a rule over ``Finding`` rows and split the match by area."""
    areas = condition_areas(condition) & set(FINDING_AREAS)
    if not areas:
        return RuleMatch(matched=False)
    scoped = findings.filter(area_q(areas))
    matched, queryset = evaluate_condition(scoped, condition or {})
    if not matched:
        return RuleMatch(matched=False)
    rows = list(
        queryset.values("severity", "scan_id", "scan__scanner_args")[:10000]
    )
    by_area: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_area.setdefault(finding_area(row["scan__scanner_args"]), []).append(row)

    result = RuleMatch(matched=True)
    for area in (AREA_CLOUD, AREA_APPLICATION_SECURITY):
        area_rows = by_area.get(area) or []
        if not area_rows:
            continue
        scan_ids = sorted({str(row["scan_id"]) for row in area_rows})
        if area == AREA_CLOUD:
            links = [cloud_findings_link(scan_ids)]
        else:
            links = _app_security_links(tenant_id, scan_ids)
        result.areas.append(
            AreaMatch(
                area=area,
                count=len(area_rows),
                severity_counts=_severity_counts(row["severity"] for row in area_rows),
                links=links,
            )
        )
    # A ``none`` or ``count_lte`` rule matches with zero findings.
    return result


def _app_security_links(tenant_id: str, scan_ids: list[str]) -> list[str]:
    from cloudsneeker_api.models import TrivyRun

    runs = TrivyRun.objects.filter(tenant_id=tenant_id, scan_id__in=scan_ids).values(
        "id", "target_id"
    )[:20]
    links = [app_security_run_link(run["target_id"], run["id"]) for run in runs]
    return links or [_ui("/application-security/findings")]


def evaluate_governance_rule(
    findings: list[Any], condition: dict[str, Any], provider_types: dict[str, str]
) -> RuleMatch:
    if AREA_GOVERNANCE not in condition_areas(condition):
        return RuleMatch(matched=False)
    matched, items = evaluate_governance_condition(findings, condition or {}, provider_types)
    if not matched:
        return RuleMatch(matched=False)
    result = RuleMatch(matched=True)
    if items:
        runs = sorted({(item.policy_id, item.run_id) for item in items})
        result.areas.append(
            AreaMatch(
                area=AREA_GOVERNANCE,
                count=len(items),
                severity_counts=_severity_counts(item.severity for item in items),
                links=[governance_run_link(policy, run) for policy, run in runs[:20]],
            )
        )
    return result


def merge_matches(*matches: RuleMatch) -> RuleMatch:
    merged = RuleMatch(matched=any(item.matched for item in matches))
    for item in matches:
        merged.areas.extend(item.areas)
    return merged


def notification_body(rule_name: str, description: str, match: RuleMatch) -> str:
    """Plain-text alert body: totals per area with links to the source pages."""
    lines = [f"Alert rule '{rule_name}' matched {match.total} finding(s)."]
    for area in match.areas:
        severities = ", ".join(
            f"{name} {count}" for name, count in sorted(area.severity_counts.items())
        )
        lines.append("")
        lines.append(f"{AREA_LABELS[area.area]}: {area.count} finding(s) ({severities})")
        for link in area.links:
            lines.append(f"  {link}")
    if description:
        lines.extend(["", description])
    return "\n".join(lines).strip()


# --- Preview and seeding ---------------------------------------------------------

SEED_FILTER_FIELDS = {
    "provider_type": ("filter[provider_type__in]", "filter[provider_type]"),
    "provider_id": ("filter[provider_id__in]", "filter[provider_id]", "filter[provider__in]"),
    "resource_regions": ("filter[region__in]", "filter[region]"),
    "resource_services": ("filter[service__in]", "filter[service]"),
    "resource_types": ("filter[resource_type__in]", "filter[resource_type]"),
    "categories": ("filter[category__in]", "filter[category]"),
    "check_id": ("filter[check_id__in]", "filter[check_id]"),
    "resource_groups": ("filter[resource_groups__in]",),
    "delta": ("filter[delta]", "filter[delta__in]"),
}


def _split(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        items: list[str] = []
        for item in value:
            items.extend(_split(item))
        return items
    if value in (None, ""):
        return []
    return [part.strip() for part in str(value).split(",") if part.strip()]


def seed_condition(filter_bag: dict[str, Any]) -> dict[str, Any]:
    """Alert condition from the filters of a findings page.

    Keeps every filter the condition language understands (not only
    severity), and the product area when the page sends one.
    """
    severity = _split(
        filter_bag.get("severity")
        or filter_bag.get("filter[severity]")
        or filter_bag.get("filter[severity__in]")
    )
    leaf: dict[str, Any] = {"severity": severity or ["critical", "high"]}
    for field_name, keys in SEED_FILTER_FIELDS.items():
        values: list[str] = []
        for key in keys:
            values.extend(_split(filter_bag.get(key)))
        if not values:
            continue
        leaf[field_name] = values[0] if field_name == "delta" else sorted(set(values))
    areas = [
        value
        for key in ("area", "filter[area]", "filter[area__in]")
        for value in _split(filter_bag.get(key))
        if value in AREAS
    ]
    if areas:
        leaf["area"] = sorted(set(areas))
    return {"op": "count_gte", "filter": leaf, "value": 1}


def preview_rule(tenant_id: str, condition: dict[str, Any]) -> dict[str, Any]:
    """What the rule would match now (latest scans and policy runs)."""
    try:
        findings = alertable_findings(tenant_id).filter(
            scan_id__in=latest_scan_ids(tenant_id)
        )
        parts = [evaluate_finding_rule(tenant_id, findings, condition)]
        if AREA_GOVERNANCE in condition_areas(condition):
            from cloudsneeker_api.services.alert_dispatch import (
                _governance_findings,
                _provider_types,
            )

            parts.append(
                evaluate_governance_rule(
                    _governance_findings(tenant_id, None),
                    condition,
                    _provider_types(tenant_id),
                )
            )
        match = merge_matches(*parts)
        counts: dict[str, int] = {}
        by_area: dict[str, int] = {}
        for area in match.areas:
            by_area[area.area] = area.count
            for severity, count in area.severity_counts.items():
                counts[severity] = counts.get(severity, 0) + count
        top_severity = max(counts, key=counts.get) if counts else None
        return {
            "summary": {
                "finding_count_total": match.total,
                "counts_by_severity": counts,
                "counts_by_area": by_area,
                "top_severity": top_severity,
                "top_findings": [],
                "matched": match.matched,
            },
            "sample_finding_ids": [],
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
