"""Assessment PDF renderer.

A4 portrait pages, landscape pages for the wide roadmap and appendix tables,
a dark cover, a clickable contents page, PDF bookmarks, document metadata, a
Confidential header label, and "Page X of Y" footers. Fonts are DejaVu Sans
(shipped with matplotlib), embedded as TrueType so any Unicode text prints.

Layout statistics (pages, pages without content, headings left alone at the
bottom of a page, contents entries, bookmarks) are recorded during the final
build pass and handed to the quality engine.

The design (palette, fonts, styles, document template, tables, KPI tiles,
charts) lives in ``reports/render/pdf_style.py`` and is shared with the
focused reports.
"""

from __future__ import annotations

import io
import logging
from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape

from cloudsneeker_api.brand import brand, pdf_author, pdf_creator
from cloudsneeker_api.reports.assessment.model import NOT_ASSESSED
from cloudsneeker_api.reports.render.pdf_style import (  # noqa: F401 - re-exported
    BRAND,
    BRAND_DARK,
    CELL_LIMIT,
    GRADE_COLORS,
    HEADING_STYLES,
    INK,
    LANDSCAPE,
    LANDSCAPE_WIDTH,
    LINE,
    MARGIN_BOTTOM,
    MARGIN_TOP,
    MARGIN_X,
    MUTED,
    PANEL,
    PORTRAIT,
    PORTRAIT_WIDTH,
    PRIORITY_COLORS,
    ROADMAP_CELL_LIMIT,
    SEVERITY_COLORS,
    TEAL,
    VIOLET,
    BrandedDoc,
    Builder,
    Gap,
    Heading,
    contents_block,
    cover_block,
    hbar_chart,
    pass_bar,
    priority_markup,
    register_fonts,
    score_ring,
    severity_markup,
    severity_strip,
    styles,
    text,
    trend_chart,
)
from cloudsneeker_api.reports.schema import ReportData
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    CondPageBreak,
    KeepTogether,
    Paragraph,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import (  # noqa: F401 - re-exported
    PageBreak,
    PageBreakIfNotEmpty,
)

logger = logging.getLogger(__name__)

# Kept for callers and tests that import the assessment template by name.
AssessmentDoc = BrandedDoc


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


def _fmt_date(value: str | None) -> str:
    if not value:
        return "-"
    try:
        return datetime.fromisoformat(value).strftime("%d %b %Y %H:%M UTC")
    except ValueError:
        return value


def cover(b: Builder, content: dict[str, Any]) -> list:
    meta = content["meta"]
    summary = content["summary"]
    score = summary.get("score")
    scope = meta.get("scope") or {}
    providers = scope.get("providers") or []
    grade = summary.get("grade") or "N/A"
    score_text = f"{score:.0f}/100" if score is not None else NOT_ASSESSED
    facts = [
        ("Security score", f"{score_text}  ·  Grade {grade}"),
        ("Assessment period", meta["period"]["label"]),
        ("Sources in scope", f"{len(providers)} provider(s) / target(s)"),
        ("Generated", _fmt_date(meta.get("generated_at"))),
        ("Classification", "Confidential"),
    ]
    return cover_block(
        b,
        "Security assessment report",
        meta["title"],
        " · ".join(meta.get("areas") or []),
        facts,
    )


def contents(b: Builder) -> list:
    return contents_block(b)


def scope_section(b: Builder, content: dict[str, Any]) -> list:
    meta = content["meta"]
    scope = meta.get("scope") or {}
    coverage = content["coverage"]
    items = b.h1("Scope and coverage", "Section 1")
    rows = [
        {"k": "Report", "v": meta["title"]},
        {"k": "Areas", "v": ", ".join(meta.get("areas") or [])},
        {"k": "Assessment period", "v": meta["period"]["label"]},
        {
            "k": "Providers and targets",
            "v": ", ".join(scope.get("providers") or []) or NOT_ASSESSED,
        },
        {
            "k": "Frameworks selected",
            "v": ", ".join(scope.get("frameworks") or []) or "All assessed frameworks",
        },
        {"k": "Stale after", "v": f"{scope.get('stale_days', 7)} days"},
        {"k": "Generated", "v": _fmt_date(meta.get("generated_at"))},
        {"k": "Report engine", "v": meta.get("engine_version")},
    ]
    items.append(
        b.table([("k", "Item", 1), ("v", "Value", 3)], rows, header_color=BRAND_DARK)
    )
    items.append(Gap(1, 4 * mm))
    for warning in coverage.get("warnings") or []:
        items += [
            b.callout(
                f"<b>Coverage warning.</b> {escape(warning)}", SEVERITY_COLORS["medium"]
            ),
            Gap(1, 2 * mm),
        ]
    items += b.table_heading("Assessed sources")
    if coverage.get("rows"):
        state_colors = {
            "Current": TEAL,
            "Stale": SEVERITY_COLORS["medium"],
            NOT_ASSESSED: MUTED,
        }
        items.append(
            b.table(
                [
                    ("area", "Area", 1.2),
                    ("source", "Source", 1.6),
                    ("type", "Type", 0.8),
                    ("stream", "Stream", 1.1),
                    ("last_assessed", "Last assessed", 1.4),
                    ("state", "State", 0.9),
                ],
                coverage["rows"],
                markup={
                    "last_assessed": lambda v, r: text(
                        _fmt_date(v) if v != NOT_ASSESSED else v
                    ),
                    "state": lambda v, r: (
                        f'<font color="#{state_colors.get(v, MUTED).hexval()[2:]}"><b>{escape(v)}</b></font>'
                    ),
                },
            )
        )
    else:
        items.append(
            b.para(f"No source in scope. Every area reads {NOT_ASSESSED.lower()}.")
        )
    return items


def summary_section(b: Builder, content: dict[str, Any]) -> list:
    summary = content["summary"]
    metrics = summary["kpis"]
    assessed = bool(metrics.get("sources_assessed"))
    items: list = [PageBreakIfNotEmpty(), *b.h1("Executive summary", "Section 2")]
    ring = score_ring(summary.get("score"), summary.get("grade") or "N/A")
    statements = summary.get("narrative") or []
    lead = [
        Paragraph(
            escape(item["text"])
            + (
                f' <font color="#64748B">[{escape(", ".join(item["refs"]))}]</font>'
                if item.get("refs")
                else ""
            ),
            b.s["body_ink"],
            bulletText="•",
        )
        for item in statements[:3]
    ]
    head = Table([[ring, lead]], colWidths=[40 * mm, PORTRAIT_WIDTH - 40 * mm])
    head.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    items += [head, Gap(1, 5 * mm)]

    def value(key: str) -> Any:
        return metrics.get(key) if assessed else None

    fix_pct = metrics.get("fix_available_pct")
    items.append(
        b.kpis(
            [
                ("Open findings", value("open_findings")),
                ("Unique affected resources", value("affected_resources")),
                ("Critical", value("critical")),
                ("High", value("high")),
                (
                    "Fix available",
                    f"{fix_pct:.0f}%" if fix_pct is not None and assessed else None,
                ),
                (
                    "Median age of critical/high (days)",
                    metrics.get("median_age_critical_high_days")
                    if assessed
                    and metrics.get("median_age_critical_high_days") is not None
                    else ("-" if assessed else None),
                ),
                (
                    "Sources assessed",
                    f"{metrics.get('sources_assessed', 0)} of {metrics.get('sources_in_scope', 0)}",
                ),
                ("Passed results", value("passed_results")),
            ]
        )
    )
    if len(statements) > 3:
        items.append(b.h2("Key observations", bookmark=False))
        for item in statements[3:]:
            refs = (
                f' <font color="#64748B">[{escape(", ".join(item["refs"]))}]</font>'
                if item.get("refs")
                else ""
            )
            items.append(
                Paragraph(escape(item["text"]) + refs, b.s["body"], bulletText="•")
            )
    items.append(b.h2("Posture by area"))
    items.append(
        b.table(
            [
                ("label", "Area", 1.5),
                ("grade", "Grade", 0.6),
                ("score", "Score", 0.6),
                ("open_findings", "Open findings", 0.9),
                ("affected_resources", "Affected resources", 1.0),
                ("critical", "Critical", 0.7),
                ("high", "High", 0.7),
            ],
            summary["areas"],
            markup={
                "grade": lambda v, r: (
                    f'<font color="#{GRADE_COLORS.get(v, MUTED).hexval()[2:]}"><b>{escape(str(v))}</b></font>'
                ),
                "score": lambda v, r: text(v) if v is not None else NOT_ASSESSED,
            },
        )
    )
    items.append(Gap(1, 2 * mm))
    items.append(
        b.para(
            "Counts are unique findings after deduplication. Unique affected resources are counted separately from findings. "
            f"Merged duplicate records: {metrics.get('duplicates_merged', 0)}.",
            "small",
        )
    )
    return items


def distribution_section(b: Builder, content: dict[str, Any]) -> list:
    dist = content["distribution"]
    items: list = [CondPageBreak(90 * mm), *b.h1("Risk distribution", "Section 3")]
    total = sum(dist["by_severity"].values())
    if not total:
        items.append(
            b.para(
                "No open findings in scope. Areas that were not assessed are listed in the coverage section."
            )
        )
        return items
    items.append(severity_strip(dist["by_severity"], PORTRAIT_WIDTH))
    palette = [
        BRAND,
        VIOLET,
        TEAL,
        colors.HexColor("#0EA5E9"),
        colors.HexColor("#6366F1"),
        colors.HexColor("#14B8A6"),
    ]
    for title, key in (
        ("By area", "by_area"),
        ("By category", "by_category"),
        ("By provider or target", "by_provider"),
    ):
        values = list(dist.get(key, {}).items())
        if not values:
            continue
        chart = hbar_chart(
            [
                (label, count, palette[i % len(palette)])
                for i, (label, count) in enumerate(values)
            ],
            PORTRAIT_WIDTH,
        )
        items.append(KeepTogether([b.h2(title, bookmark=False), chart, Gap(1, 3 * mm)]))
    return items


def trend_section(b: Builder, content: dict[str, Any]) -> list:
    trend = content.get("trend")
    if trend is None:
        return []
    items: list = [CondPageBreak(95 * mm), *b.h1("Trend", "Section 4")]
    points = trend.get("points") or []
    if len(points) < 2:
        items.append(
            b.para(
                "Not enough assessment history in the period to show a trend. "
                + NOT_ASSESSED
                + "."
            )
        )
        return items
    items.append(trend_chart(points, PORTRAIT_WIDTH))
    change = trend.get("change")
    if change:
        items.append(
            b.callout(
                f"Like-for-like change ({escape(change['from_date'])} to {escape(change['to_date'])}): open findings "
                f"{change['total_from']:,} → {change['total_to']:,}; critical and high {change['critical_high_from']:,} → "
                f"{change['critical_high_to']:,}.",
                TEAL,
            )
        )
    items += b.bullets(trend.get("notes") or [], "small")
    return items


def _risk_card(b: Builder, index: int, risk: dict[str, Any]) -> list:
    rec = risk["recommendation"]
    impact = rec.get("business_impact") or {}
    head = (
        f"{priority_markup(risk['priority'])}  ·  {severity_markup(risk['severity'])}  ·  "
        f'<font color="#64748B">{escape(risk.get("window") or "")} · ref {escape(risk["lead_ref"])}</font>'
    )
    facts = [
        {"k": "Finding references", "v": risk["refs"]},
        {"k": "Check / rule", "v": risk["check_id"]},
        {
            "k": "Scope",
            "v": f"{risk['findings']} finding(s), {risk['resources']} resource(s), {risk['accounts']} account(s)/target(s)",
        },
        {"k": "Suggested owner", "v": rec.get("suggested_owner")},
        {
            "k": "SLA / target date",
            "v": f"{rec.get('sla_days')} day(s) · {rec.get('target_date')}",
        },
        {"k": "Priority justification", "v": rec.get("justification")},
    ]
    if rec.get("advisory", {}).get("cvss_published"):
        facts.append(
            {"k": "Advisory-published CVSS", "v": rec["advisory"]["cvss_published"]}
        )
    block: list = [
        CondPageBreak(80 * mm),
        b.h2(f"{index}. {risk['title']}"),
        b.para(head, "body_ink"),
        Gap(1, 1.5 * mm),
        b.table(
            [("k", "Item", 1), ("v", "Detail", 3.2)], facts, header_color=BRAND_DARK
        ),
        Gap(1, 2 * mm),
    ]
    if rec.get("issue"):
        block += [b.h3("What the issue is"), b.para(text(rec["issue"]))]
    block += [b.h3("Why it matters"), b.para(text(rec.get("why_it_matters")))]
    block.append(b.h3("Business impact"))
    if impact.get("confirmed"):
        block.append(
            b.para(f"<b>Confirmed (scanner evidence):</b> {text(impact['confirmed'])}")
        )
    block.append(b.para(f"<b>Potential:</b> {text(impact.get('potential'))}"))
    block.append(b.h3("How to fix"))
    block += [
        Paragraph(text(step), b.s["body"], bulletText=f"{n}.")
        for n, step in enumerate(rec.get("instructions") or [], start=1)
    ]
    for command in rec.get("commands") or []:
        code = escape(command["code"]).replace("\n", "<br/>")
        block.append(Gap(1, 1.5 * mm))
        block.append(b.para(f"<b>{escape(command['label'])}</b>", "small"))
        snippet = Table([[Paragraph(code, b.s["mono"])]], colWidths=[PORTRAIT_WIDTH])
        snippet.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EEF2F8")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        block.append(snippet)
    if rec.get("placeholder_note"):
        block.append(b.para(f"<i>{escape(rec['placeholder_note'])}</i>", "small"))
    block.append(b.h3("Validate the fix"))
    block += b.bullets(rec.get("validation") or [])
    block.append(b.h3("Prevent recurrence"))
    block += b.bullets(rec.get("prevention") or [])
    block.append(
        b.para(f"<b>Expected outcome:</b> {text(rec.get('expected_outcome'))}")
    )
    if rec.get("references"):
        block.append(
            b.para(
                "References: " + ", ".join(escape(url) for url in rec["references"]),
                "small",
            )
        )
    block.append(Gap(1, 5 * mm))
    return block


def top_risks_section(b: Builder, content: dict[str, Any]) -> list:
    risks = content.get("top_risks")
    if risks is None:
        return []
    if not risks:
        return [
            CondPageBreak(50 * mm),
            *b.h1("Top risks", "Section 5"),
            b.para("No open finding requires scheduling in this scope."),
        ]
    items: list = [PageBreakIfNotEmpty(), *b.h1("Top risks", "Section 5")]
    items.append(
        b.para(
            "Issues are ranked by evidence-based priority, then severity and spread. Each issue lists the finding "
            "references it covers; the appendix and the CSV export hold every finding.",
            "small",
        )
    )
    for index, risk in enumerate(risks, start=1):
        items += _risk_card(b, index, risk)
    return items


def posture_section(b: Builder, content: dict[str, Any]) -> list:
    posture = content.get("posture")
    if not posture:
        return []
    items: list = []
    for area, data in posture.items():
        if not data.get("assessed"):
            items += [
                CondPageBreak(60 * mm),
                *b.h1(f"{data['label']} posture", "Posture"),
            ]
            items.append(
                b.callout(
                    f"{escape(data['label'])} was {NOT_ASSESSED.lower()} in this period. No result is shown as zero.",
                    MUTED,
                )
            )
            items.append(Gap(1, 4 * mm))
            continue
        items += [PageBreakIfNotEmpty(), *b.h1(f"{data['label']} posture", "Posture")]
        ring = score_ring(data.get("score"), data.get("grade") or "N/A", 28 * mm)
        stats = b.kpis(
            [
                ("Open findings", data["open_findings"]),
                ("Affected resources", data["affected_resources"]),
                ("Passed results", data.get("passed_results")),
                (
                    "Resources with a passed result",
                    data.get("passed_resources")
                    if data.get("passed_resources") is not None
                    else "-",
                ),
            ],
            columns=2,
            width=PORTRAIT_WIDTH - 36 * mm,
        )
        head = Table([[ring, stats]], colWidths=[36 * mm, PORTRAIT_WIDTH - 36 * mm])
        head.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        items += [head, severity_strip(data["by_severity"], PORTRAIT_WIDTH)]
        if data.get("by_category"):
            items.append(b.h2(f"{data['label']}: categories", bookmark=False))
            items.append(
                hbar_chart(
                    [(k, v, VIOLET) for k, v in data["by_category"].items()],
                    PORTRAIT_WIDTH,
                )
            )
        if data.get("top_issues"):
            items += b.table_heading(f"{data['label']}: leading issues", bookmark=False)
            items.append(
                b.table(
                    [
                        ("priority", "Priority", 0.6),
                        ("severity", "Severity", 0.8),
                        ("title", "Issue", 2.6),
                        ("resources", "Resources", 0.7),
                        ("findings", "Findings", 0.7),
                        ("lead_ref", "Ref", 0.6),
                    ],
                    data["top_issues"],
                    markup={
                        "severity": lambda v, r: severity_markup(v),
                        "priority": lambda v, r: priority_markup(v),
                    },
                )
            )
        if data.get("by_account"):
            items.append(b.h2(f"{data['label']}: by account or target", bookmark=False))
            items.append(
                hbar_chart(
                    [(k, v, BRAND) for k, v in data["by_account"].items()],
                    PORTRAIT_WIDTH,
                )
            )
    return items


def compliance_section(b: Builder, content: dict[str, Any]) -> list:
    compliance = content.get("compliance")
    if compliance is None:
        return []
    items: list = [PageBreakIfNotEmpty(), *b.h1("Compliance frameworks", "Compliance")]
    items.append(
        b.callout(
            f"<b>Not a certification.</b> {escape(compliance['disclaimer'])}", VIOLET
        )
    )
    items.append(Gap(1, 3 * mm))
    items += b.table_heading("Assessed frameworks")
    if compliance["assessed"]:
        items.append(
            b.table(
                [
                    ("framework", "Framework", 2.2),
                    ("passed", "Passed", 0.6),
                    ("failed", "Failed", 0.6),
                    ("manual", "Manual", 0.6),
                    ("total", "Requirements", 0.8),
                    ("pass_pct", "Pass rate", 0.7),
                ],
                compliance["assessed"],
                markup={
                    "pass_pct": lambda v, r: (
                        f"{v:.1f}%" if v is not None else NOT_ASSESSED
                    )
                },
            )
        )
        items.append(
            b.para(
                "Pass rate = passed / (passed + failed). Manual requirements are excluded, not counted as passed.",
                "small",
            )
        )
    else:
        items.append(
            b.para(
                f"No framework has requirement results in scope ({NOT_ASSESSED.lower()})."
            )
        )
    if compliance["enabled_not_assessed"]:
        items.append(b.h2("Selected but not assessed", bookmark=False))
        items.append(b.para(escape(", ".join(compliance["enabled_not_assessed"]))))
    items.append(b.h2("Available, not assessed", bookmark=False))
    items.append(
        b.para(
            f"{compliance['available_count']} further framework(s) are available for the providers in scope but have no "
            "results in this period. They are not part of any figure in this report.",
            "small",
        )
    )
    return items


def ai_section(b: Builder, content: dict[str, Any]) -> list:
    ai = content.get("ai")
    if ai is None:
        return []
    items: list = [
        CondPageBreak(70 * mm),
        *b.h1("Seeker AI insights", "Interpretation"),
    ]
    items.append(
        b.callout(
            "<b>AI-generated, separate from scanner facts.</b> "
            + escape(ai.get("message") or "")
            + (f" Model: {escape(ai['model'])}." if ai.get("model") else ""),
            VIOLET,
        )
    )
    for insight in ai.get("insights") or []:
        kind = "Fact" if insight["kind"] == "fact" else "Interpretation"
        items.append(
            Paragraph(
                f"<b>{kind}.</b> {escape(insight['statement'])} "
                f'<font color="#64748B">[{escape(", ".join(insight["citations"]))}]</font>',
                b.s["body"],
                bulletText="•",
            )
        )
    return items


ROADMAP_COLUMNS = [
    ("priority", "Pri.", 0.4),
    ("lead_ref", "Ref", 0.65),
    ("title", "Issue", 1.5),
    ("resource", "Resource(s)", 1.2),
    ("justification", "Justification", 1.8),
    ("instructions", "Instructions", 2.2),
    ("suggested_owner", "Suggested owner", 0.9),
    ("sla_target", "SLA / target", 1.0),
    ("validation", "Validation", 1.5),
    ("expected_outcome", "Expected outcome", 1.25),
]


def roadmap_section(b: Builder, content: dict[str, Any]) -> list:
    windows = content.get("roadmap")
    if windows is None:
        return []
    if not any(window["items"] for window in windows):
        return [
            CondPageBreak(50 * mm),
            *b.h1("Remediation roadmap", "Plan"),
            b.para("No open finding needs a remediation window in this scope."),
        ]
    items: list = [
        PageBreakIfNotEmpty(nextTemplate="landscape"),
        *b.h1("Remediation roadmap", "Plan"),
    ]
    items.append(
        b.para(
            "One row per issue; an issue may cover several findings and resources (see the references). Owners, SLAs, "
            "and target dates are suggestions counted from the report date.",
            "small",
        )
    )
    for window in windows:
        title = f"{window['priority']} · {window['label']}"
        if not window["items"]:
            items += [b.h2(title), b.para("No issue in this window.")]
            continue
        items += b.table_heading(title, room=85 * mm)
        rows = [
            {
                **item,
                "resource": f"{item['resource']} ({item['resources']} resource(s), {item['findings']} finding(s))",
                "sla_target": f"{item['sla_days']} day(s), by {item['target_date']}",
            }
            for item in window["items"]
        ]
        items.append(
            b.table(
                ROADMAP_COLUMNS,
                rows,
                width=LANDSCAPE_WIDTH,
                markup={"priority": lambda v, r: priority_markup(v)},
                cell_limit=ROADMAP_CELL_LIMIT,
            )
        )
        if window["total_items"] > len(window["items"]):
            items.append(
                b.para(
                    f"{window['total_items'] - len(window['items'])} further issue(s) in this window are in the CSV export.",
                    "small",
                )
            )
    return items


APPENDIX_PDF_COLUMNS = [
    ("ref", "Ref", 0.6),
    ("severity", "Severity", 0.75),
    ("title", "Finding", 1.8),
    ("check_id", "Check / rule", 1.75),
    ("resource", "Resource", 1.8),
    ("account", "Account / target", 1.0),
    ("region", "Region", 0.9),
    ("priority", "Pri.", 0.4),
    ("triage_status", "Triage", 0.65),
    ("first_seen", "First seen", 0.85),
    ("fix", "Fix", 0.9),
]


def appendix_section(b: Builder, content: dict[str, Any]) -> list:
    appendix = content.get("appendix")
    if appendix is None:
        return []
    if not appendix["groups"]:
        return [
            CondPageBreak(50 * mm),
            *b.h1("Technical appendix", "Appendix"),
            b.para("No open findings in scope."),
        ]
    items: list = [
        PageBreakIfNotEmpty(nextTemplate="landscape"),
        *b.h1("Technical appendix", "Appendix"),
    ]
    note = f"{appendix['total']:,} open finding(s), grouped by category and severity."
    if appendix["truncated"]:
        note += f" The first {appendix['printed']:,} (most severe first) are printed; the CSV export holds all of them."
    items.append(b.para(note, "small"))
    for group in appendix["groups"]:
        items += [
            CondPageBreak(60 * mm),
            b.h2(f"{group['label']} ({group['count']:,})"),
        ]
        first = True
        for bucket in group["severities"]:
            if not bucket["rows"]:
                continue
            label = f"{bucket['severity'].capitalize()}: {bucket['count']:,}"
            if len(bucket["rows"]) < bucket["count"]:
                label += f" (first {len(bucket['rows']):,} printed)"
            if first:
                # Grouped with the category heading, which reserved room above.
                items.append(Paragraph(escape(label), b.s["h3_free"]))
                first = False
            else:
                items += b.table_heading(label, level=3, room=50 * mm)
            items.append(
                b.table(
                    APPENDIX_PDF_COLUMNS,
                    bucket["rows"],
                    width=LANDSCAPE_WIDTH,
                    markup={
                        "severity": lambda v, r: severity_markup(v),
                        "priority": lambda v, r: priority_markup(v),
                    },
                )
            )
    return items


def methodology_section(b: Builder, content: dict[str, Any]) -> list:
    accuracy = content["accuracy"]
    items: list = [
        PageBreakIfNotEmpty(nextTemplate="portrait"),
        *b.h1("Methodology and data quality", "Method"),
    ]
    items += b.bullets(content.get("methodology") or [])
    items.append(b.h2("Data accuracy"))
    polarity = accuracy["polarity"]
    rows = [
        {"k": "Records analyzed", "v": accuracy["input_records"]},
        {
            "k": "Duplicates merged",
            "v": f"{accuracy['duplicates_merged']} (into {accuracy['duplicate_groups']} finding(s))",
        },
        {"k": "Muted (excluded from open counts)", "v": accuracy["muted"]},
        {"k": "Manual review (not assessed)", "v": polarity["manual"]},
        {"k": "Unrecognized status (excluded)", "v": polarity["unknown_status"]},
        {"k": "Pass / fail conflicts", "v": polarity["conflicts"]},
        {"k": "Load bound reached", "v": "Yes" if accuracy["truncated"] else "No"},
    ]
    items.append(
        b.table([("k", "Measure", 2), ("v", "Value", 2)], rows, header_color=BRAND_DARK)
    )
    items += b.table_heading("Reconciliation", room=40 * mm)
    items.append(
        b.table(
            [("rule", "Rule", 1.2), ("ok", "Result", 0.6), ("detail", "Detail", 3)],
            accuracy["reconciliation"],
            markup={
                "ok": lambda v, r: (
                    '<font color="#0D9488"><b>Holds</b></font>'
                    if v
                    else '<font color="#B71C1C"><b>Fails</b></font>'
                )
            },
        )
    )
    quality = content.get("quality")
    items.append(b.h2("Report quality control"))
    if quality:
        tone = {
            "pass": TEAL,
            "warn": SEVERITY_COLORS["medium"],
            "fail": SEVERITY_COLORS["critical"],
        }[quality["status"]]
        verdict = "Distributable" if quality["distributable"] else "Not distributable"
        items.append(b.callout(f"<b>{verdict}.</b> {escape(quality['summary'])}", tone))
        items.append(Gap(1, 2 * mm))
        status_colors = {
            "pass": "#0D9488",
            "warn": "#FB8C00",
            "fail": "#B71C1C",
            "pending": "#64748B",
        }
        items.append(
            b.table(
                [
                    ("category", "Area", 0.8),
                    ("id", "Check", 1.3),
                    ("status", "Status", 0.6),
                    ("detail", "Detail", 3),
                ],
                quality["checks"],
                markup={
                    "status": lambda v, r: (
                        f'<font color="{status_colors.get(v, "#64748B")}"><b>{escape(v.upper())}</b></font>'
                    )
                },
            )
        )
    return items


def story(content: dict[str, Any]) -> list:
    """Every flowable of the report, in order."""
    b = Builder()
    flow: list = []
    flow += cover(b, content)
    flow.append(PageBreak(nextTemplate="portrait"))
    flow += contents(b)
    flow.append(PageBreak())
    flow += scope_section(b, content)
    flow += summary_section(b, content)
    flow += distribution_section(b, content)
    flow += trend_section(b, content)
    flow += top_risks_section(b, content)
    flow += posture_section(b, content)
    flow += compliance_section(b, content)
    flow += ai_section(b, content)
    flow += roadmap_section(b, content)
    flow += appendix_section(b, content)
    flow += methodology_section(b, content)
    return flow


def build_pdf(
    content: dict[str, Any], total_pages: int | None = None
) -> tuple[bytes, dict[str, Any]]:
    """Render the report and return ``(pdf bytes, layout statistics)``.

    Args:
        content: Report content.
        total_pages: Page count of a previous render, printed in footers
            until this render measures its own.
    """
    register_fonts()
    meta = content["meta"]
    buffer = io.BytesIO()
    doc = AssessmentDoc(
        buffer,
        {
            "title": meta["title"],
            "generated": _fmt_date(meta.get("generated_at")),
            "period": meta["period"]["label"],
            "engine_version": meta.get("engine_version", ""),
            "total_pages": total_pages,
        },
        title=f"{meta['title']} - {brand.name}",
        author=pdf_author(),
        subject=f"{meta['title']} ({meta['period']['label']})",
        creator=pdf_creator(),
        keywords=f"security assessment, {meta['report_type']}, confidential, {brand.slug}",
        leftMargin=MARGIN_X,
        rightMargin=MARGIN_X,
        topMargin=MARGIN_TOP,
        bottomMargin=MARGIN_BOTTOM,
    )
    doc.multiBuild(story(content), maxPasses=6)
    return buffer.getvalue(), dict(doc.layout)


def render_assessment_pdf(data: ReportData) -> bytes:
    """Run-pipeline entry point: render, run quality control, and re-render.

    The first render measures the layout; quality control then evaluates the
    content and that layout; the second render prints the quality results.
    The stored quality reflects the layout of the final file.
    """
    from cloudsneeker_api.reports.assessment.quality import evaluate

    content = data.extra["assessment"]
    findings = getattr(data, "assessment_findings", []) or []
    # First pass: quality without layout, so the checks table has its size.
    content["quality"] = evaluate(content, findings, None)
    pdf_bytes, layout = build_pdf(content)
    content["quality"] = evaluate(content, findings, layout)
    for _ in range(3):
        pdf_bytes, layout = build_pdf(content, layout["pages"])
        content["quality"] = evaluate(content, findings, layout)
        if layout.get("page_total_consistent"):
            break
    content["layout"] = layout
    return pdf_bytes
