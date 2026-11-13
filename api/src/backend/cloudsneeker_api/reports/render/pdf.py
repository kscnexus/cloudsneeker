"""Branded PDF renderer for every report type.

The four security assessments have their own story in
``reports/assessment/render_pdf.py``. Every other report type (executive,
cloud posture, compliance, the Application Security reports, governance,
exceptions, remediation, licenses, SBOM) is laid out here with the same
design from ``reports/render/pdf_style.py``: dark cover, clickable contents,
bookmarks, brand header with the Confidential label, "Page X of Y" footer,
KPI tiles, severity colours, long tables with a repeating header row, and
vector charts.
"""

from __future__ import annotations

import io
import os
from typing import Any
from xml.sax.saxutils import escape

from cloudsneeker_api.brand import brand, pdf_author, pdf_creator
from cloudsneeker_api.reports.data.common import GRADE_BANDS, SEVERITY_WEIGHTS
from cloudsneeker_api.reports.render.pdf_style import (
    BRAND,
    BRAND_DARK,
    GRADE_COLORS,
    LANDSCAPE_WIDTH,
    MARGIN_BOTTOM,
    MARGIN_TOP,
    MARGIN_X,
    MUTED,
    PORTRAIT_WIDTH,
    PRIORITY_COLORS,
    SEVERITY_COLORS,
    TEAL,
    BrandedDoc,
    Builder,
    Gap,
    contents_block,
    cover_block,
    grade_markup,
    hbar_chart,
    priority_markup,
    register_fonts,
    ring_head,
    score_ring,
    severity_markup,
    severity_strip,
    text,
    trend_chart,
)
from cloudsneeker_api.reports.schema import (
    SEVERITY_ORDER,
    STATUS_SCOPE_LABELS,
    ReportData,
    ReportFilters,
    ReportTable,
)
from reportlab.lib.units import mm
from reportlab.platypus import CondPageBreak, Paragraph
from reportlab.platypus.flowables import PageBreak, PageBreakIfNotEmpty

NOT_SCORED = "Not scored"
WIDE_FIELDS = frozenset(
    {"title", "detail", "description", "remediation", "action", "impact", "why"}
)
# Longest text kept in one detail-table cell.
DETAIL_CELL_LIMIT = 300

REPORT_KICKERS: dict[str, str] = {
    "executive": "Executive security report",
    "cloud_posture": "Cloud security report",
    "compliance": "Compliance report",
    "sca": "Application security report",
    "sast": "Application security report",
    "container": "Application security report",
    "iac": "Application security report",
    "secrets": "Application security report",
    "governance": "Governance report",
    "exceptions": "Risk exceptions report",
    "remediation": "Remediation report",
    "licenses": "License compliance report",
    "sbom": "Software inventory report",
}
STATUS_LABELS: dict[str, str] = {
    "fail": "Failed",
    "pass": "Passed",
    "muted": "Muted",
    "manual": "Manual review",
}
SOURCE_COLUMNS: list[tuple[str, str]] = [
    ("label", "Area"),
    ("provider", "Source"),
    ("mode", "Type"),
    ("provider_type", "Provider type"),
    ("grade", "Grade"),
    ("score", "Score"),
    ("open_issues", "Open issues"),
    ("fail", "Failed"),
    ("pass", "Passed"),
    ("critical", "Critical"),
    ("high", "High"),
    ("policies", "Policies"),
    ("resources", "Resources"),
    ("coverage", "Coverage"),
]


def pdf_max_rows() -> int:
    """Row bound per PDF table (``REPORT_PDF_MAX_ROWS``, default 500)."""
    try:
        return max(1, int(os.environ.get("REPORT_PDF_MAX_ROWS", "500")))
    except ValueError:
        return 500


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _window(filters: ReportFilters) -> str:
    if not (filters.date_from or filters.date_to):
        return "All time"
    start = filters.date_from.date().isoformat() if filters.date_from else "start"
    end = filters.date_to.date().isoformat() if filters.date_to else "today"
    return f"{start} to {end}"


def _generated(data: ReportData) -> str:
    return data.generated_at.strftime("%d %b %Y %H:%M UTC")


def _kpi_value(value: Any) -> Any:
    # Focused reports use None for "no value"; print a dash, as before.
    return "-" if value is None else value


def _score_text(data: ReportData) -> str:
    if data.score is not None:
        return f"{data.score:.0f}/100  ·  Grade {data.grade}"
    if data.grade and data.grade != "N/A":
        return f"Grade {data.grade}"
    return NOT_SCORED


def _severity_cell(value: Any, row: dict[str, Any]) -> str:
    if not value:
        return "-"
    return severity_markup(str(value).lower())


def _grade_cell(value: Any, row: dict[str, Any]) -> str:
    return grade_markup(value) if value else "-"


def _score_cell(value: Any, row: dict[str, Any]) -> str:
    return text(value) if value is not None else "-"


def _priority_cell(value: Any, row: dict[str, Any]) -> str:
    if isinstance(value, str) and value in PRIORITY_COLORS:
        return priority_markup(value)
    return text(value)


CELL_MARKUP = {
    "severity": _severity_cell,
    "grade": _grade_cell,
    "priority": _priority_cell,
}


def _table(
    b: Builder,
    table: ReportTable,
    *,
    width: float,
    bookmark: bool = True,
) -> list:
    """Heading, bounded long table, and the truncation note."""
    items = b.table_heading(table.title, bookmark=bookmark)
    if not table.rows:
        items.append(b.para("No rows."))
        return items
    bound = pdf_max_rows()
    rows = table.rows[:bound]
    columns = [
        (field, header, 2.0 if field in WIDE_FIELDS else 1.0)
        for field, header in table.columns
    ]
    markup = {
        field: CELL_MARKUP[field] for field, _ in table.columns if field in CELL_MARKUP
    }
    items.append(
        b.table(
            columns,
            rows,
            markup=markup,
            width=width,
            cell_limit=DETAIL_CELL_LIMIT,
        )
    )
    shown = len(rows)
    total = max(table.total, shown)
    if shown < total:
        items.append(
            b.para(
                f"Showing the first {shown:,} of {total:,} rows. The Excel and CSV "
                "exports carry the full list.",
                "small",
            )
        )
    items.append(Gap(1, 4 * mm))
    return items


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


def cover(b: Builder, data: ReportData) -> list:
    filters = data.filters
    facts = [
        ("Security score", _score_text(data)),
        ("Period", _window(filters)),
        (
            "Sources",
            f"{len(filters.provider_ids)} selected"
            if filters.provider_ids
            else "All visible",
        ),
        ("Severity floor", (filters.severity_floor or "all").capitalize()),
    ]
    if filters.compliance_id:
        facts.append(("Framework", filters.compliance_id))
    if filters.target_name:
        facts.append(("Target", filters.target_name))
    if filters.status_scope:
        facts.append(
            (
                "Finding status",
                STATUS_SCOPE_LABELS.get(filters.status_scope, filters.status_scope),
            )
        )
    facts += [
        ("Generated", _generated(data)),
        ("Classification", "Confidential"),
    ]
    subtitle = data.headline if len(data.headline) <= 240 else data.headline[:239] + "…"
    return cover_block(
        b,
        REPORT_KICKERS.get(data.report_type, "Security report"),
        data.title,
        subtitle,
        facts,
    )


def summary_section(b: Builder, data: ReportData) -> list:
    items: list = b.h1("Executive summary", "Summary")
    headline = Paragraph(escape(data.headline or "-"), b.s["body_ink"])
    if data.score is not None:
        grade = data.grade if data.grade in GRADE_COLORS else "N/A"
        items += [ring_head(score_ring(data.score, grade), headline), Gap(1, 5 * mm)]
    elif not data.is_empty:
        items += [b.callout(escape(data.headline or "-")), Gap(1, 4 * mm)]
    if data.is_empty:
        message = data.empty_state or ""
        items.append(b.callout(f"<b>Nothing to report.</b> {escape(message)}", MUTED))
        items.append(Gap(1, 2 * mm))
        items.append(
            b.para(
                "No figure in this report is shown as zero for lack of data. Widen the "
                "period or the sources, or run a scan, and generate the report again.",
                "small",
            )
        )
        return items
    if data.kpis:
        items.append(
            b.kpis(
                [
                    (key.replace("_", " ").capitalize(), _kpi_value(value))
                    for key, value in data.kpis.items()
                ]
            )
        )
    statuses = [
        (STATUS_LABELS.get(key, key.replace("_", " ").capitalize()), value)
        for key, value in data.status_totals.items()
    ]
    if any(value for _, value in statuses):
        items.append(b.h2("Results by status", bookmark=False))
        items.append(b.kpis(statuses))
    return items


def distribution_section(b: Builder, data: ReportData) -> list:
    totals = {sev: int(data.severity_totals.get(sev, 0) or 0) for sev in SEVERITY_ORDER}
    if not any(totals.values()):
        return []
    items: list = [CondPageBreak(80 * mm), *b.h1("Risk distribution", "Risk")]
    items.append(severity_strip(totals, PORTRAIT_WIDTH))
    items.append(b.h2("Open findings by severity", bookmark=False))
    items.append(
        hbar_chart(
            [
                (sev.capitalize(), totals[sev], SEVERITY_COLORS[sev])
                for sev in SEVERITY_ORDER
            ],
            PORTRAIT_WIDTH,
        )
    )
    return items


def trend_section(b: Builder, data: ReportData) -> list:
    if not data.trend:
        return []
    items: list = [CondPageBreak(95 * mm), *b.h1("Trend", "Trend")]
    if len(data.trend) < 2:
        point = data.trend[0]
        items.append(
            b.para(
                f"Only one scan day in range ({text(point.get('date'))}): "
                f"{point.get('fail', 0)} open, {point.get('pass', 0)} passed. "
                "Trends appear after more scans."
            )
        )
        return items
    points = [
        {
            "date": str(point.get("date", "")),
            "total": int(point.get("fail", 0) or 0),
            "critical": int(point.get("critical", 0) or 0),
            "high": int(point.get("high", 0) or 0),
            "comparable": True,
        }
        for point in data.trend
    ]
    items.append(trend_chart(points, PORTRAIT_WIDTH, comparable_note=False))
    first, last = data.trend[0], data.trend[-1]
    change = last["fail"] - first["fail"]
    direction = "down" if change < 0 else "up" if change > 0 else "flat"
    sentence = (
        f"Open findings went {direction} from {first['fail']:,} on {escape(str(first['date']))} "
        f"to {last['fail']:,} on {escape(str(last['date']))}."
    )
    if any(point.get("pass") for point in data.trend):
        sentence += (
            f" Passed results: {first.get('pass', 0):,} → {last.get('pass', 0):,}."
        )
    items.append(b.callout(sentence, TEAL if change <= 0 else SEVERITY_COLORS["high"]))
    return items


def _risk_card(b: Builder, index: int, risk: dict[str, Any]) -> list:
    severity = str(risk.get("severity") or "medium").lower()
    title = str(risk.get("title") or risk.get("check_id") or "-")
    facts = [
        {"k": "Check / rule", "v": risk.get("check_id")},
        {
            "k": "Affected",
            "v": f"{risk.get('resources', 0)} resource(s), {risk.get('findings', 0)} finding(s)",
        },
    ]
    if risk.get("service"):
        facts.append({"k": "Service", "v": risk["service"]})
    block: list = [
        CondPageBreak(60 * mm),
        b.h2(f"{index}. {title}"),
        b.para(severity_markup(severity), "body_ink"),
        Gap(1, 1.5 * mm),
        b.table(
            [("k", "Item", 1), ("v", "Detail", 3.2)], facts, header_color=BRAND_DARK
        ),
        Gap(1, 2 * mm),
        b.h3("Business impact"),
        b.para(text(risk.get("impact"))),
        b.h3("Recommended fix"),
        b.para(text(risk.get("remediation"), 600)),
        Gap(1, 4 * mm),
    ]
    return block


def top_risks_section(b: Builder, data: ReportData) -> list:
    if not data.top_risks:
        return []
    items: list = [PageBreakIfNotEmpty(), *b.h1("Top risks", "Risks")]
    items.append(
        b.para(
            "Ranked by severity and spread. The detail tables and the exports hold "
            "every finding.",
            "small",
        )
    )
    for index, risk in enumerate(data.top_risks, start=1):
        items += _risk_card(b, index, risk)
    return items


def sources_section(b: Builder, data: ReportData) -> list:
    if not data.sources:
        return []
    sample = data.sources[0]
    columns = [(field, header) for field, header in SOURCE_COLUMNS if field in sample][
        :8
    ]
    items: list = [CondPageBreak(60 * mm), *b.h1("Coverage and sources", "Coverage")]
    if not columns:
        items.append(b.para(f"{len(data.sources)} source(s) in scope."))
        return items
    weights = [
        (field, header, 1.6 if field in ("label", "provider") else 1.0)
        for field, header in columns
    ]
    items.append(b.h2("Breakdown by source", bookmark=False))
    items.append(
        b.table(
            weights,
            data.sources[: pdf_max_rows()],
            markup={"grade": _grade_cell, "score": _score_cell},
        )
    )
    return items


def compliance_section(b: Builder, data: ReportData) -> list:
    if not data.compliance:
        return []
    items: list = [CondPageBreak(70 * mm), *b.h1("Compliance posture", "Compliance")]
    scored = [item for item in data.compliance if item.get("pass_pct") is not None]
    if scored:
        items.append(b.h2("Requirements passing (%)", bookmark=False))
        items.append(
            hbar_chart(
                [
                    (
                        str(item.get("compliance_id")),
                        round(float(item["pass_pct"])),
                        TEAL
                        if item["pass_pct"] >= 80
                        else BRAND
                        if item["pass_pct"] >= 60
                        else SEVERITY_COLORS["medium"],
                    )
                    for item in scored[:15]
                ],
                PORTRAIT_WIDTH,
            )
        )
        items.append(Gap(1, 3 * mm))
    table = ReportTable(
        key="compliance_posture",
        title="Frameworks",
        columns=[
            ("compliance_id", "Framework"),
            ("pass_pct", "Passing %"),
            ("passed", "Passed"),
            ("failed", "Failed"),
            ("manual", "Manual"),
        ],
        rows=[
            {
                **item,
                "pass_pct": item.get("pass_pct")
                if item.get("pass_pct") is not None
                else "Not assessed",
            }
            for item in data.compliance
        ],
        total=len(data.compliance),
    )
    items += _table(b, table, width=PORTRAIT_WIDTH, bookmark=False)
    return items


def actions_section(b: Builder, data: ReportData) -> list:
    if not data.remediation:
        return []
    items: list = [CondPageBreak(50 * mm), *b.h1("Recommended next actions", "Actions")]
    for item in data.remediation:
        why = item.get("why")
        suffix = (
            f' <font color="#64748B"><i>{escape(str(why))}</i></font>' if why else ""
        )
        title = item.get("title")
        prefix = f"<b>{escape(str(title))}:</b> " if title and not why else ""
        severity = item.get("severity")
        tag = f"{severity_markup(str(severity).lower())}  ·  " if severity else ""
        items.append(
            Paragraph(
                f"{tag}{prefix}{escape(str(item.get('action') or ''))}{suffix}",
                b.s["body"],
                bulletText=f"{item.get('priority', '')}.",
            )
        )
    return items


def details_section(b: Builder, data: ReportData) -> list:
    tables = [table for table in data.tables if table.key != "top_risks"]
    if not tables:
        return []
    items: list = [
        PageBreakIfNotEmpty(nextTemplate="landscape"),
        *b.h1("Detailed results", "Appendix"),
    ]
    for table in tables:
        items += _table(b, table, width=LANDSCAPE_WIDTH)
    return items


def methodology_section(b: Builder, data: ReportData) -> list:
    weights = ", ".join(f"{sev} {SEVERITY_WEIGHTS[sev]:g}" for sev in SEVERITY_ORDER)
    bands = ", ".join(f"{grade} at {floor:.0f}+" for floor, grade in GRADE_BANDS)
    items: list = [
        PageBreakIfNotEmpty(nextTemplate="portrait"),
        *b.h1("Appendix: methodology", "Method"),
        b.para(
            "Data comes from the latest completed scan of each source in scope "
            "(per provider, and per scan type for application security). Muted "
            "findings are excluded from open counts."
        ),
    ]
    if data.filters.status_scope:
        label = STATUS_SCOPE_LABELS.get(
            data.filters.status_scope, data.filters.status_scope
        )
        items.append(
            b.callout(
                f"<b>Finding status scope: {escape(label)}.</b> Failed-finding counts, "
                "risks, and detail tables only include findings in this scope; a "
                "grade is given for active findings only.",
                BRAND,
            )
        )
        items.append(Gap(1, 2 * mm))
    items += [
        b.para(
            f"The security score weights findings by severity ({weights}). With "
            "pass/fail results it is the weighted share of passing checks; for "
            "vulnerability and secret scans, which report failures only, it "
            "decreases as weighted open findings grow. Grades: "
            f"{bands}, F below."
        ),
        b.para(
            f"Generated by {escape(brand.name)} on {_generated(data)}.",
            "small",
        ),
    ]
    return items


def story(data: ReportData) -> list:
    """Every flowable of a focused report, in order."""
    b = Builder()
    flow: list = []
    flow += cover(b, data)
    flow.append(PageBreak(nextTemplate="portrait"))
    flow += contents_block(b)
    flow.append(PageBreak())
    flow += summary_section(b, data)
    if not data.is_empty:
        flow += distribution_section(b, data)
        flow += trend_section(b, data)
        flow += top_risks_section(b, data)
        flow += sources_section(b, data)
        flow += compliance_section(b, data)
        flow += actions_section(b, data)
        flow += details_section(b, data)
    flow += methodology_section(b, data)
    return flow


def build_pdf(
    data: ReportData, total_pages: int | None = None
) -> tuple[bytes, dict[str, Any]]:
    """Render a focused report and return ``(pdf bytes, layout statistics)``.

    Args:
        data: Assembled report data.
        total_pages: Page count of a previous render, printed in footers
            until this render measures its own.
    """
    register_fonts()
    buffer = io.BytesIO()
    generated = _generated(data)
    doc = BrandedDoc(
        buffer,
        {
            "title": data.title,
            "generated": generated,
            "period": f"Period: {_window(data.filters)}",
            "cover_note": f"{brand.name}  ·  Generated {generated}",
            "total_pages": total_pages,
        },
        title=f"{data.title} - {brand.name}",
        author=pdf_author(),
        subject=data.title,
        creator=pdf_creator(),
        keywords=f"security, report, {data.report_type}, confidential, {brand.slug}",
        leftMargin=MARGIN_X,
        rightMargin=MARGIN_X,
        topMargin=MARGIN_TOP,
        bottomMargin=MARGIN_BOTTOM,
    )
    doc.multiBuild(story(data), maxPasses=6)
    return buffer.getvalue(), dict(doc.layout)


def render_pdf(data: ReportData) -> bytes:
    """Render a report to PDF bytes.

    Assessment reports go to their own renderer. Every other type is laid out
    here; the document is rebuilt until the "Page X of Y" totals match the
    final page count.

    Args:
        data: Assembled report data.

    Returns:
        PDF document bytes.
    """
    if "assessment" in data.extra:
        from cloudsneeker_api.reports.assessment.render_pdf import (
            render_assessment_pdf,
        )

        return render_assessment_pdf(data)
    pdf_bytes, layout = build_pdf(data)
    for _ in range(3):
        if layout.get("page_total_consistent"):
            break
        pdf_bytes, layout = build_pdf(data, layout["pages"])
    return pdf_bytes
