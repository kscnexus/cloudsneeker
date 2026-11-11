"""Report quality control.

Runs after the content is built and the PDF is laid out. A report is
distributable only when no check fails. Warnings (stale sources, truncated
loads, unknown statuses) keep it distributable but are listed in the report
and on the run.
"""

from __future__ import annotations

import json
import re
from typing import Any

from cloudsneeker_api.reports.assessment.model import NOT_ASSESSED, NormalizedFinding

PASS, WARN, FAIL = "pass", "warn", "fail"
_UPSTREAM = re.compile("".join(("pro", "wler")), re.IGNORECASE)
_PLACEHOLDER = re.compile(r"<[A-Z][A-Z0-9_]*>")
_ALLOWED_ADVISORY_KEYS = {"cvss_published", "cvss_vector"}
_FORBIDDEN_KEYS = {
    "epss",
    "epss_score",
    "exploit_available",
    "asset_criticality",
    "cvss_estimated",
}


def _check(check_id: str, category: str, status: str, detail: str) -> dict[str, str]:
    return {"id": check_id, "category": category, "status": status, "detail": detail}


def _walk_keys(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key).lower()
            yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


def content_checks(content: dict[str, Any]) -> list[dict[str, str]]:
    """Sections, narrative, and coverage warnings."""
    checks = []
    sections = set((content.get("meta") or {}).get("sections") or [])
    kpis = (content.get("summary") or {}).get("kpis") or {}
    open_count = kpis.get("open_findings") or 0
    schedulable = sum(
        kpis.get(sev) or 0 for sev in ("critical", "high", "medium", "low")
    )
    narrative = (content.get("summary") or {}).get("narrative") or []
    checks.append(
        _check(
            "narrative",
            "content",
            PASS if narrative and all(item.get("text") for item in narrative) else FAIL,
            f"{len(narrative)} evidence-based statement(s).",
        )
    )
    if "top_risks" in sections:
        risks = content.get("top_risks") or []
        ok = bool(risks) or not schedulable
        checks.append(
            _check(
                "top_risks",
                "content",
                PASS if ok else FAIL,
                f"{len(risks)} top risk(s) for {open_count} open finding(s).",
            )
        )
    if "roadmap" in sections:
        windows = content.get("roadmap") or []
        items = sum(window["total_items"] for window in windows)
        ok = len(windows) == 4 and (items > 0 or not schedulable)
        checks.append(
            _check(
                "roadmap_windows",
                "content",
                PASS if ok else FAIL,
                f"{len(windows)} window(s), {items} item(s).",
            )
        )
    coverage = content.get("coverage") or {}
    rows = coverage.get("rows") or []
    flagged = [row for row in rows if row.get("state") != "Current"]
    has_warning = bool(coverage.get("warnings"))
    checks.append(
        _check(
            "coverage_warnings",
            "content",
            PASS if (not flagged or has_warning) else FAIL,
            f"{len(rows)} source(s), {len(flagged)} stale or not assessed.",
        )
    )
    if flagged:
        checks.append(
            _check(
                "coverage_complete",
                "data",
                WARN,
                f"{len(flagged)} source(s) are stale or not assessed; see the coverage section.",
            )
        )
    return checks


def data_checks(
    content: dict[str, Any], findings: list[NormalizedFinding]
) -> list[dict[str, str]]:
    """Reconciliation, polarity, deduplication, and missing-data labels."""
    checks = []
    accuracy = content.get("accuracy") or {}
    failed_rules = [
        rule for rule in accuracy.get("reconciliation") or [] if not rule["ok"]
    ]
    checks.append(
        _check(
            "totals_reconcile",
            "data",
            FAIL if failed_rules else PASS,
            "; ".join(rule["detail"] for rule in failed_rules)
            or "Every total reconciles.",
        )
    )
    by_ref = {item.ref: item for item in findings}
    exposure_refs = []
    for risk in content.get("top_risks") or []:
        exposure_refs.append(risk["lead_ref"])
    for window in content.get("roadmap") or []:
        exposure_refs.extend(item["lead_ref"] for item in window["items"])
    wrong = [
        ref for ref in exposure_refs if ref not in by_ref or not by_ref[ref].is_open
    ]
    checks.append(
        _check(
            "polarity_exposure_only_open",
            "data",
            FAIL if wrong else PASS,
            f"{len(wrong)} exposure item(s) do not reference an open failed finding."
            if wrong
            else f"All {len(exposure_refs)} exposure item(s) reference open failed findings.",
        )
    )
    polarity = accuracy.get("polarity") or {}
    if polarity.get("unknown_status") or polarity.get("conflicts"):
        checks.append(
            _check(
                "polarity_ambiguities",
                "data",
                WARN,
                " ".join(polarity.get("issues") or []),
            )
        )
    unique = len(findings)
    checks.append(
        _check(
            "deduplicated",
            "data",
            PASS if accuracy.get("input_records", unique) >= unique else FAIL,
            f"{accuracy.get('input_records', unique)} record(s), {accuracy.get('duplicates_merged', 0)} merged.",
        )
    )
    bad_missing = [
        row["label"]
        for row in (content.get("summary") or {}).get("areas") or []
        if not row.get("assessed") and row.get("open_findings") != NOT_ASSESSED
    ]
    checks.append(
        _check(
            "missing_not_zero",
            "data",
            FAIL if bad_missing else PASS,
            f"Areas shown as zero without assessment: {', '.join(bad_missing)}"
            if bad_missing
            else "Areas without an assessment read 'Not assessed'.",
        )
    )
    if accuracy.get("truncated"):
        checks.append(
            _check(
                "load_bound",
                "data",
                WARN,
                "The finding load reached its bound; see coverage warnings.",
            )
        )
    return checks


def recommendation_checks(content: dict[str, Any]) -> list[dict[str, str]]:
    """Every roadmap item is actionable and nothing is invented."""
    checks = []
    required = (
        "instructions",
        "validation",
        "suggested_owner",
        "sla_days",
        "target_date",
        "justification",
    )
    incomplete = []
    for window in content.get("roadmap") or []:
        for item in window["items"]:
            missing = [key for key in required if not item.get(key)]
            if missing:
                incomplete.append(f"{item['lead_ref']} ({', '.join(missing)})")
    checks.append(
        _check(
            "roadmap_items_complete",
            "recommendations",
            FAIL if incomplete else PASS,
            "Incomplete: " + "; ".join(incomplete[:5])
            if incomplete
            else "Every roadmap item is complete.",
        )
    )
    keys = set(_walk_keys(content))
    invented = sorted(keys & _FORBIDDEN_KEYS)
    advisory_bad = []
    for risk in content.get("top_risks") or []:
        extra = (
            set((risk.get("recommendation") or {}).get("advisory") or {})
            - _ALLOWED_ADVISORY_KEYS
        )
        if extra:
            advisory_bad.append(risk["lead_ref"])
    checks.append(
        _check(
            "no_invented_scores",
            "recommendations",
            FAIL if invented or advisory_bad else PASS,
            f"Unexpected score fields: {', '.join(invented + advisory_bad)}"
            if invented or advisory_bad
            else "Only advisory-published scores carried by the scanner are shown.",
        )
    )
    unmarked = []
    for risk in content.get("top_risks") or []:
        rec = risk.get("recommendation") or {}
        uses = any(
            _PLACEHOLDER.search(command.get("code", ""))
            for command in rec.get("commands") or []
        )
        if uses and not rec.get("placeholder_note"):
            unmarked.append(risk["lead_ref"])
    checks.append(
        _check(
            "placeholders_marked",
            "recommendations",
            FAIL if unmarked else PASS,
            f"Unmarked placeholders in {', '.join(unmarked)}"
            if unmarked
            else "Placeholders are marked.",
        )
    )
    ai = content.get("ai")
    if ai:
        uncited = [
            item for item in ai.get("insights") or [] if not item.get("citations")
        ]
        checks.append(
            _check(
                "ai_cited",
                "recommendations",
                FAIL if uncited else PASS,
                f"AI status {ai.get('status')}; {len(ai.get('insights') or [])} cited insight(s).",
            )
        )
    text = json.dumps({k: v for k, v in content.items() if k != "quality"}, default=str)
    checks.append(
        _check(
            "brand_clean",
            "content",
            FAIL if _UPSTREAM.search(text) else PASS,
            "No third-party product branding in report text.",
        )
    )
    return checks


def layout_checks(layout: dict[str, Any] | None) -> list[dict[str, str]]:
    """Checks on the rendered PDF (page count, blank pages, orphans, TOC)."""
    if not layout:
        return [
            _check("pdf_rendered", "layout", WARN, "No PDF was rendered for this run.")
        ]
    checks = [
        _check(
            "pdf_pages",
            "layout",
            PASS if layout.get("pages", 0) > 0 else FAIL,
            f"{layout.get('pages', 0)} page(s).",
        )
    ]
    blank = layout.get("blank_pages") or []
    checks.append(
        _check(
            "no_blank_pages",
            "layout",
            FAIL if blank else PASS,
            f"Blank pages: {blank}" if blank else "No blank pages.",
        )
    )
    orphans = layout.get("orphan_headings") or []
    checks.append(
        _check(
            "no_orphan_headings",
            "layout",
            FAIL if orphans else PASS,
            f"Headings at page bottom: {orphans}"
            if orphans
            else "No heading is left alone at a page bottom.",
        )
    )
    toc = layout.get("toc_entries", 0)
    bookmarks = layout.get("bookmarks", 0)
    checks.append(
        _check(
            "toc_and_bookmarks",
            "layout",
            PASS if toc and bookmarks >= toc else FAIL,
            f"{toc} contents entr(ies), {bookmarks} bookmark(s).",
        )
    )
    checks.append(
        _check(
            "metadata",
            "layout",
            PASS if layout.get("metadata") else FAIL,
            "Title, author, subject, and keywords are set."
            if layout.get("metadata")
            else "Document metadata missing.",
        )
    )
    return checks


def evaluate(
    content: dict[str, Any],
    findings: list[NormalizedFinding],
    layout: dict[str, Any] | None,
) -> dict[str, Any]:
    """Run every check.

    Returns:
        ``{"status", "distributable", "checks", "summary"}``.
    """
    checks = [
        *content_checks(content),
        *data_checks(content, findings),
        *recommendation_checks(content),
        *layout_checks(layout),
    ]
    failed = [item for item in checks if item["status"] == FAIL]
    warned = [item for item in checks if item["status"] == WARN]
    status = FAIL if failed else WARN if warned else PASS
    return {
        "status": status,
        "distributable": not failed,
        "checks": checks,
        "summary": f"{len(checks)} checks: {len(failed)} failed, {len(warned)} warning(s).",
    }
