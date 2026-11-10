"""Optional Seeker AI insights, kept apart from scanner facts.

The model only sees a compact fact sheet built from the report (metrics and
top issues with their references). It must answer in JSON; every insight has
to cite at least one finding reference or metric key from that fact sheet and
say whether it is a fact or an interpretation. Insights that cite anything
else are dropped. When the tenant has no LLM configured, the call fails, or
nothing valid comes back, the section says so explicitly instead of
guessing.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

MAX_INSIGHTS = 6
MAX_STATEMENT = 600
_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)

SYSTEM_PROMPT = (
    "You are a security analyst writing for executives. You receive a JSON fact "
    "sheet produced by automated scanners. Use only those facts. Never invent "
    "CVSS, EPSS, exploit availability, asset criticality, counts, or dates. "
    'Reply with JSON only: {"insights": [{"statement": str, "kind": "fact" | '
    '"interpretation", "citations": [str]}], "insufficient_data": bool}. Each '
    "citation must be a finding reference (like F-0001) or a metric key that "
    "appears in the fact sheet. Write at most six short insights. If the facts "
    "do not support an insight, set insufficient_data to true and return no insights."
)


def fact_sheet(content: dict[str, Any]) -> dict[str, Any]:
    """The only data the model sees."""
    summary = content.get("summary") or {}
    metrics = {
        key: value
        for key, value in (summary.get("kpis") or {}).items()
        if isinstance(value, (int, float, str)) or value is None
    }
    issues = [
        {
            "ref": risk.get("lead_ref"),
            "title": risk.get("title"),
            "severity": risk.get("severity"),
            "priority": risk.get("priority"),
            "resources": risk.get("resources"),
            "findings": risk.get("findings"),
            "category": risk.get("category"),
        }
        for risk in (content.get("top_risks") or [])[:10]
    ]
    return {
        "report": (content.get("meta") or {}).get("title"),
        "period": ((content.get("meta") or {}).get("period") or {}).get("label"),
        "metrics": metrics,
        "areas": [
            {
                k: row.get(k)
                for k in (
                    "label",
                    "assessed",
                    "score",
                    "open_findings",
                    "critical",
                    "high",
                )
            }
            for row in summary.get("areas") or []
        ],
        "top_issues": issues,
        "coverage_warnings": (content.get("coverage") or {}).get("warnings") or [],
    }


def _allowed_citations(facts: dict[str, Any]) -> set[str]:
    allowed = set(facts["metrics"])
    allowed |= {issue["ref"] for issue in facts["top_issues"] if issue.get("ref")}
    return allowed


def parse_insights(reply: str, facts: dict[str, Any]) -> list[dict[str, Any]]:
    """Keep only well-formed insights whose citations exist in the facts."""
    match = _JSON_BLOCK.search(reply or "")
    if not match:
        return []
    try:
        payload = json.loads(match.group(0))
    except ValueError:
        return []
    allowed = _allowed_citations(facts)
    insights = []
    for item in (payload.get("insights") or [])[: MAX_INSIGHTS * 2]:
        if not isinstance(item, dict):
            continue
        statement = str(item.get("statement") or "").strip()[:MAX_STATEMENT]
        kind = str(item.get("kind") or "").lower()
        citations = [str(c) for c in item.get("citations") or [] if str(c) in allowed]
        if not statement or kind not in ("fact", "interpretation") or not citations:
            continue
        insights.append({"statement": statement, "kind": kind, "citations": citations})
        if len(insights) >= MAX_INSIGHTS:
            break
    return insights


def _unavailable(status: str, message: str) -> dict[str, Any]:
    return {"status": status, "message": message, "insights": [], "model": None}


def ai_insights(tenant_id: str, content: dict[str, Any]) -> dict[str, Any]:
    """Ask Seeker AI for cited insights about the report.

    Args:
        tenant_id: Tenant UUID string.
        content: Report content (from ``build_content``).

    Returns:
        ``{"status", "message", "insights", "model"}``. ``status`` is
        ``ok``, ``insufficient_data``, or ``unavailable``.
    """
    facts = fact_sheet(content)
    if not facts["metrics"].get("sources_assessed"):
        return _unavailable(
            "insufficient_data",
            "Insufficient data: no source in scope has a completed assessment.",
        )
    try:
        from cloudsneeker_api.services.custodian_ai import (
            PolicyGenerationError,
            complete_chat,
            resolve_llm_settings,
        )
    except ImportError:  # pragma: no cover - optional dependency missing
        return _unavailable(
            "unavailable", "Seeker AI is not available in this deployment."
        )
    try:
        settings = resolve_llm_settings(tenant_id)
        reply = complete_chat(
            settings,
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(facts, default=str)},
            ],
        )
    except PolicyGenerationError as exc:
        if getattr(exc, "code", "") == "llm_error":
            return _unavailable(
                "unavailable",
                "Seeker AI did not answer; the report was generated without insights.",
            )
        return _unavailable("unavailable", str(exc))
    except Exception:  # noqa: BLE001 - the report must still generate
        logger.exception("Seeker AI insights failed tenant=%s", tenant_id)
        return _unavailable(
            "unavailable",
            "Seeker AI did not answer; the report was generated without insights.",
        )
    insights = parse_insights(reply, facts)
    if not insights:
        return {
            **_unavailable(
                "insufficient_data",
                "Insufficient data: Seeker AI returned no insight that could be tied "
                "to a finding reference or metric in this report.",
            ),
            "model": settings.model_id,
        }
    return {
        "status": "ok",
        "message": "Generated by Seeker AI from this report's data. Each insight cites its sources.",
        "insights": insights,
        "model": settings.model_id,
    }
