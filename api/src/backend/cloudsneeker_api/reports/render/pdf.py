"""Branded PDF renderer.

Reuses the upstream report building blocks in ``tasks.jobs.reports`` (fonts,
paragraph styles, tables, charts, and the brand logo / footer hooks) so
Cloudsneeker reports look like the compliance reports already shipped.
"""

from __future__ import annotations

import gc
import io
import os
from typing import Any

from cloudsneeker_api.brand import (
    brand,
    pdf_author,
    pdf_creator,
    pdf_footer,
    report_logo_path,
)
from cloudsneeker_api.reports.data.common import GRADE_BANDS, SEVERITY_WEIGHTS
from cloudsneeker_api.reports.schema import SEVERITY_ORDER, ReportData, ReportTable
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer
from tasks.jobs.reports import base as upstream_base
from tasks.jobs.reports.base import create_pdf_styles
from tasks.jobs.reports.charts import (
    create_horizontal_bar_chart,
    create_vertical_bar_chart,
    get_chart_color_for_percentage,
)
from tasks.jobs.reports.components import (
    ColumnConfig,
    create_data_table,
    create_info_table,
    create_summary_table,
    escape_html,
    get_color_for_compliance,
    truncate_text,
)
from tasks.jobs.reports.config import COLOR_BLUE

SEVERITY_HEX: dict[str, str] = {
    "critical": "#B71C1C",
    "high": "#E53935",
    "medium": "#FB8C00",
    "low": "#FDD835",
    "informational": "#90A4AE",
}

WIDE_FIELDS = frozenset(
    {"title", "detail", "description", "remediation", "action", "impact", "why"}
)
CONTENT_WIDTH = 7.0 * inch
ASSETS_IMG_DIR = os.path.normpath(
    os.path.join(os.path.dirname(upstream_base.__file__), "../../assets/img")
)


def pdf_max_rows() -> int:
    """Row bound per PDF table (``REPORT_PDF_MAX_ROWS``, default 500)."""
    try:
        return max(1, int(os.environ.get("REPORT_PDF_MAX_ROWS", "500")))
    except ValueError:
        return 500


class _BrandedDocTemplate(SimpleDocTemplate):
    """Document template that records the page of every H1 heading."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.headings: list[tuple[str, int]] = []

    def afterFlowable(self, flowable: Any) -> None:  # noqa: N802 - reportlab API
        if isinstance(flowable, Paragraph) and flowable.style.name == "CustomH1":
            self.headings.append((flowable.getPlainText(), self.page))


def _cell_style(styles: dict[str, ParagraphStyle]) -> ParagraphStyle:
    return ParagraphStyle(
        "CloudsneekerCell",
        parent=styles["normal_center"],
        fontSize=8,
        leading=10,
    )


def _score_color(score: float | None) -> colors.Color:
    if score is None:
        return colors.Color(0.5, 0.5, 0.5)
    return get_color_for_compliance(score)


def _format_value(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.1f}"
    return str(value)


def _column_widths(columns: list[tuple[str, str]]) -> list[float]:
    weights = [2.0 if field in WIDE_FIELDS else 1.0 for field, _ in columns]
    total = sum(weights) or 1.0
    return [CONTENT_WIDTH * weight / total for weight in weights]


def _table_flowables(
    table: ReportTable, styles: dict[str, ParagraphStyle], cell_style: ParagraphStyle
) -> list:
    elements: list = [Paragraph(escape_html(table.title), styles["h2"])]
    if not table.rows:
        elements.append(Paragraph("No rows.", styles["normal"]))
        return elements
    bound = pdf_max_rows()
    rows = [
        {
            field: truncate_text(_format_value(row.get(field)), 300)
            for field, _ in table.columns
        }
        for row in table.rows[:bound]
    ]
    widths = _column_widths(table.columns)
    columns = [
        ColumnConfig(header, width, field, align="LEFT")
        for (field, header), width in zip(table.columns, widths, strict=True)
    ]
    elements.append(
        create_data_table(rows, columns, header_color=COLOR_BLUE, normal_style=cell_style)
    )
    shown = len(rows)
    if shown < table.total:
        elements.append(
            Paragraph(
                f"Showing the first {shown} of {table.total} rows. The Excel and "
                "CSV exports carry the full list.",
                styles["normal"],
            )
        )
    elements.append(Spacer(1, 0.2 * inch))
    return elements


def _severity_chart(data: ReportData) -> bytes | None:
    values = [data.severity_totals.get(severity, 0) for severity in SEVERITY_ORDER]
    if not any(values):
        return None
    peak = max(values)
    buffer = create_vertical_bar_chart(
        labels=[severity.capitalize() for severity in SEVERITY_ORDER],
        values=values,
        ylabel="Open findings",
        xlabel="Severity",
        colors=[SEVERITY_HEX[severity] for severity in SEVERITY_ORDER],
        y_limit=(0, peak * 1.15 if peak else 1),
        show_labels=False,
        rotation=0,
        figsize=(8, 4),
    )
    return buffer.getvalue()


def _trend_chart(points: list[dict[str, Any]]) -> bytes:
    import matplotlib.pyplot as plt  # Agg backend set by tasks.jobs.reports.charts

    fig, ax = plt.subplots(figsize=(8, 3.5))
    dates = [point["date"] for point in points]
    ax.plot(dates, [point["fail"] for point in points], marker="o", label="Open", color="#E53935")
    ax.plot(
        dates,
        [point["critical"] + point["high"] for point in points],
        marker="o",
        label="Critical + high",
        color="#B71C1C",
    )
    if any(point["pass"] for point in points):
        ax.plot(dates, [point["pass"] for point in points], marker="o", label="Passed", color="#4CAF50")
    ax.set_ylabel("Findings")
    ax.grid(True, alpha=0.3)
    ax.legend()
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    buffer = io.BytesIO()
    try:
        fig.savefig(buffer, format="png", dpi=150, bbox_inches="tight")
        buffer.seek(0)
    finally:
        plt.close(fig)
        gc.collect()
    return buffer.getvalue()


def _compliance_chart(posture: list[dict[str, Any]]) -> bytes | None:
    scored = [item for item in posture if item.get("pass_pct") is not None][:15]
    if not scored:
        return None
    buffer = create_horizontal_bar_chart(
        labels=[str(item["compliance_id"]) for item in scored],
        values=[float(item["pass_pct"]) for item in scored],
        xlabel="Requirements passing (%)",
        color_func=get_chart_color_for_percentage,
        label_fontsize=10,
    )
    return buffer.getvalue()


def _cover(data: ReportData, styles: dict[str, ParagraphStyle]) -> list:
    elements: list = []
    logo_path = report_logo_path(ASSETS_IMG_DIR)
    if os.path.exists(logo_path):
        elements.append(Image(logo_path, width=5 * inch, height=1 * inch))
    elements.append(Spacer(1, 0.5 * inch))
    elements.append(Paragraph(escape_html(data.title), styles["title"]))
    elements.append(Spacer(1, 0.3 * inch))
    filters = data.filters
    window = "All time"
    if filters.date_from or filters.date_to:
        start = filters.date_from.date().isoformat() if filters.date_from else "start"
        end = filters.date_to.date().isoformat() if filters.date_to else "today"
        window = f"{start} to {end}"
    rows = [
        ("Product", brand.name),
        ("Generated", data.generated_at.strftime("%Y-%m-%d %H:%M UTC")),
        ("Sources", f"{len(filters.provider_ids)} selected" if filters.provider_ids else "All visible"),
        ("Period", window),
        ("Severity floor", (filters.severity_floor or "all").capitalize()),
    ]
    if filters.compliance_id:
        rows.append(("Framework", filters.compliance_id))
    elements.append(
        create_info_table(rows, normal_style=styles["normal_center"])
    )
    elements.append(Spacer(1, 0.4 * inch))
    grade_text = data.grade if data.score is None else f"{data.grade} ({data.score:.0f}/100)"
    elements.append(
        create_summary_table("Security grade:", grade_text, _score_color(data.score))
    )
    return elements


def _image(png: bytes, width: float, height: float) -> Image:
    return Image(io.BytesIO(png), width=width, height=height)


def _summary(
    data: ReportData, styles: dict[str, ParagraphStyle], charts: dict[str, bytes]
) -> list:
    elements: list = [Paragraph("Executive summary", styles["h1"])]
    elements.append(Paragraph(escape_html(data.headline), styles["normal"]))
    elements.append(Spacer(1, 0.2 * inch))
    if data.is_empty:
        return elements
    kpi_rows = [
        (key.replace("_", " ").capitalize(), _format_value(value))
        for key, value in data.kpis.items()
    ]
    if kpi_rows:
        elements.append(create_info_table(kpi_rows, normal_style=styles["normal_center"]))
        elements.append(Spacer(1, 0.2 * inch))
    chart = charts.get("severity")
    if chart is not None:
        elements.append(Paragraph("Open findings by severity", styles["h2"]))
        elements.append(_image(chart, 6 * inch, 3 * inch))
    return elements


def _risks(data: ReportData, styles: dict[str, ParagraphStyle], cell: ParagraphStyle) -> list:
    if not data.top_risks:
        return []
    elements: list = [Paragraph("Top risks", styles["h1"])]
    for index, risk in enumerate(data.top_risks, start=1):
        severity = str(risk.get("severity", "medium"))
        color = SEVERITY_HEX.get(severity, "#FB8C00")
        title = escape_html(str(risk.get("title") or risk.get("check_id")))
        elements.append(
            Paragraph(
                f'{index}. <font color="{color}">[{severity.upper()}]</font> {title}',
                styles["h3"],
            )
        )
        elements.append(
            Paragraph(
                f"<b>Affected:</b> {risk.get('resources', 0)} resource(s), "
                f"{risk.get('findings', 0)} finding(s). "
                f"<b>Business impact:</b> {escape_html(str(risk.get('impact') or ''))}",
                styles["normal"],
            )
        )
        elements.append(
            Paragraph(
                f"<b>Recommended fix:</b> {escape_html(truncate_text(str(risk.get('remediation') or ''), 600))}",
                styles["normal"],
            )
        )
    return elements


def _sources(data: ReportData, styles: dict[str, ParagraphStyle], cell: ParagraphStyle) -> list:
    if not data.sources:
        return []
    sample = data.sources[0]
    preferred = [
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
    columns = [(field, header) for field, header in preferred if field in sample][:8]
    table = ReportTable(
        key="sources",
        title="Breakdown by source",
        columns=columns,
        rows=data.sources,
        total=len(data.sources),
    )
    return [Paragraph("Coverage and sources", styles["h1"]), *_table_flowables(table, styles, cell)]


def _trend(
    data: ReportData, styles: dict[str, ParagraphStyle], charts: dict[str, bytes]
) -> list:
    if not data.trend:
        return []
    elements: list = [Paragraph("Trend", styles["h1"])]
    if len(data.trend) < 2:
        point = data.trend[0]
        elements.append(
            Paragraph(
                f"Only one scan day in range ({point['date']}): {point['fail']} open, "
                f"{point['pass']} passed. Trends appear after more scans.",
                styles["normal"],
            )
        )
        return elements
    first, last = data.trend[0], data.trend[-1]
    change = last["fail"] - first["fail"]
    direction = "down" if change < 0 else "up" if change > 0 else "flat"
    elements.append(
        Paragraph(
            f"Open findings went {direction} from {first['fail']} on {first['date']} "
            f"to {last['fail']} on {last['date']}.",
            styles["normal"],
        )
    )
    chart = charts.get("trend")
    if chart is not None:
        elements.append(_image(chart, 6.5 * inch, 2.8 * inch))
    return elements


def _compliance(
    data: ReportData, styles: dict[str, ParagraphStyle], charts: dict[str, bytes]
) -> list:
    if not data.compliance:
        return []
    elements: list = [Paragraph("Compliance posture", styles["h1"])]
    chart = charts.get("compliance")
    if chart is not None:
        scored = sum(1 for item in data.compliance if item.get("pass_pct") is not None)
        height = min(8.0, 0.4 * min(scored, 15) + 1.2)
        elements.append(_image(chart, 6.5 * inch, height * inch))
    return elements


def _actions(data: ReportData, styles: dict[str, ParagraphStyle]) -> list:
    if not data.remediation:
        return []
    elements: list = [Paragraph("Recommended next actions", styles["h1"])]
    for item in data.remediation:
        why = item.get("why")
        suffix = f" <i>{escape_html(str(why))}</i>" if why else ""
        title = item.get("title")
        prefix = f"<b>{escape_html(str(title))}:</b> " if title and not why else ""
        elements.append(
            Paragraph(
                f"{item['priority']}. {prefix}{escape_html(str(item.get('action') or ''))}{suffix}",
                styles["normal"],
            )
        )
    return elements


def _appendix(data: ReportData, styles: dict[str, ParagraphStyle]) -> list:
    weights = ", ".join(f"{sev} {SEVERITY_WEIGHTS[sev]:g}" for sev in SEVERITY_ORDER)
    bands = ", ".join(f"{grade} at {floor:.0f}+" for floor, grade in GRADE_BANDS)
    return [
        Paragraph("Appendix: methodology", styles["h1"]),
        Paragraph(
            "Data comes from the latest completed scan of each source in scope "
            "(per provider, and per scan type for application security). Muted "
            "findings are excluded from open counts.",
            styles["normal"],
        ),
        Paragraph(
            f"The security score weights findings by severity ({weights}). With "
            "pass/fail results it is the weighted share of passing checks; for "
            "vulnerability and secret scans, which report failures only, it "
            "decreases as weighted open findings grow. Grades: "
            f"{bands}, F below.",
            styles["normal"],
        ),
        Paragraph(
            f"Generated by {escape_html(brand.name)} on "
            f"{data.generated_at.strftime('%Y-%m-%d %H:%M UTC')}.",
            styles["normal"],
        ),
    ]


def _charts(data: ReportData) -> dict[str, bytes]:
    """Render every chart once; story passes wrap the PNG bytes in new Images."""
    if data.is_empty:
        return {}
    charts: dict[str, bytes] = {}
    severity = _severity_chart(data)
    if severity is not None:
        charts["severity"] = severity
    if len(data.trend) >= 2:
        charts["trend"] = _trend_chart(data.trend)
    compliance = _compliance_chart(data.compliance)
    if compliance is not None:
        charts["compliance"] = compliance
    return charts


def _toc(
    entries: list[tuple[str, int]], styles: dict[str, ParagraphStyle], cell: ParagraphStyle
) -> list:
    rows = [{"section": title, "page": str(page) if page else ""} for title, page in entries]
    columns = [
        ColumnConfig("Section", 5.5 * inch, "section", align="LEFT"),
        ColumnConfig("Page", 1.0 * inch, "page", align="RIGHT"),
    ]
    return [
        Paragraph("Contents", styles["title"]),
        create_data_table(rows, columns, header_color=COLOR_BLUE, normal_style=cell),
    ]


def _story(
    data: ReportData,
    styles: dict[str, ParagraphStyle],
    cell: ParagraphStyle,
    charts: dict[str, bytes],
    toc_entries: list[tuple[str, int]],
) -> list:
    elements: list = [*_cover(data, styles), PageBreak()]
    elements += [*_toc(toc_entries, styles, cell), PageBreak()]
    elements += _summary(data, styles, charts)
    if not data.is_empty:
        elements += _trend(data, styles, charts)
        elements += _risks(data, styles, cell)
        elements += _sources(data, styles, cell)
        elements += _compliance(data, styles, charts)
        elements += _actions(data, styles)
        detail_tables = [table for table in data.tables if table.key != "top_risks"]
        if detail_tables:
            elements += [PageBreak(), Paragraph("Detailed results", styles["h1"])]
            for table in detail_tables:
                elements += _table_flowables(table, styles, cell)
    elements += [PageBreak(), *_appendix(data, styles)]
    return elements


def _heading_titles(story: list) -> list[str]:
    return [
        item.getPlainText()
        for item in story
        if isinstance(item, Paragraph) and item.style.name == "CustomH1"
    ]


def _add_footer(canvas_obj: Any, doc_template: Any) -> None:
    canvas_obj.saveState()
    width, _ = doc_template.pagesize
    left_text = f"Page {doc_template.page}"
    right_text = pdf_footer()
    canvas_obj.setFont("PlusJakartaSans", 9)
    canvas_obj.setFillColorRGB(0.4, 0.4, 0.4)
    canvas_obj.drawString(30, 20, left_text)
    text_width = canvas_obj.stringWidth(right_text, "PlusJakartaSans", 9)
    canvas_obj.drawString(width - text_width - 30, 20, right_text)
    canvas_obj.restoreState()


def _build(data: ReportData, story: list) -> tuple[bytes, list[tuple[str, int]]]:
    buffer = io.BytesIO()
    doc = _BrandedDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        title=f"{data.title} - {brand.name}",
        author=pdf_author(),
        subject=data.title,
        creator=pdf_creator(),
        keywords=f"security,report,{data.report_type},{brand.slug}",
    )
    doc.build(story, onFirstPage=_add_footer, onLaterPages=_add_footer)
    return buffer.getvalue(), doc.headings


def render_pdf(data: ReportData) -> bytes:
    """Render a report to PDF bytes.

    The document is built twice: the first pass records the page of every
    section heading (the contents page holds one placeholder row per
    heading, so pagination does not move), the second prints those pages.

    Args:
        data: Assembled report data.

    Returns:
        PDF document bytes.
    """
    styles = create_pdf_styles()
    cell = _cell_style(styles)
    charts = _charts(data)
    titles = _heading_titles(_story(data, styles, cell, charts, []))
    _, headings = _build(data, _story(data, styles, cell, charts, [(t, 0) for t in titles]))
    pdf_bytes, _ = _build(data, _story(data, styles, cell, charts, headings))
    return pdf_bytes
