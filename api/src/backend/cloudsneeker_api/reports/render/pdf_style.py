"""Shared PDF design for every Cloudsneeker report.

One visual language for the security assessments
(``reports/assessment/render_pdf.py``) and the focused reports
(``reports/render/pdf.py``): palette, embedded DejaVu fonts, paragraph
styles, the dark cover, the brand header and "Page X of Y" footer, section
headings that become bookmarks and contents entries, KPI tiles, severity and
priority markup, the long-table style with a repeating header row, and the
vector charts.
"""

from __future__ import annotations

import io
import logging
import os
from typing import Any
from xml.sax.saxutils import escape

from cloudsneeker_api.brand import brand
from cloudsneeker_api.reports.assessment.model import NOT_ASSESSED
from cloudsneeker_api.reports.schema import SEVERITY_ORDER
from reportlab.graphics.shapes import (
    Circle,
    Drawing,
    Line,
    PolyLine,
    Rect,
    String,
    Wedge,
)
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate,
    CondPageBreak,
    Flowable,
    Frame,
    LongTable,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.doctemplate import ActionFlowable
from reportlab.platypus.flowables import PageBreak, PageBreakIfNotEmpty
from reportlab.platypus.tableofcontents import TableOfContents

logger = logging.getLogger(__name__)

# Palette: deep navy ink with the brand blue, violet, and teal accents.
INK = colors.HexColor("#0B1220")
INK_SOFT = colors.HexColor("#334155")
MUTED = colors.HexColor("#64748B")
LINE = colors.HexColor("#E2E8F0")
PANEL = colors.HexColor("#F4F7FB")
BRAND = colors.HexColor("#2583FF")
BRAND_DARK = colors.HexColor("#1652B8")
VIOLET = colors.HexColor("#7C5CFF")
TEAL = colors.HexColor("#0D9488")
COVER_BG = colors.HexColor("#070B16")
WHITE = colors.white

SEVERITY_COLORS: dict[str, colors.Color] = {
    "critical": colors.HexColor("#B71C1C"),
    "high": colors.HexColor("#E53935"),
    "medium": colors.HexColor("#FB8C00"),
    "low": colors.HexColor("#E0B000"),
    "informational": colors.HexColor("#90A4AE"),
}
PRIORITY_COLORS: dict[str, colors.Color] = {
    "P0": colors.HexColor("#B71C1C"),
    "P1": colors.HexColor("#E53935"),
    "P2": colors.HexColor("#FB8C00"),
    "P3": colors.HexColor("#2583FF"),
}
GRADE_COLORS: dict[str, colors.Color] = {
    "A": colors.HexColor("#0D9488"),
    "B": colors.HexColor("#2583FF"),
    "C": colors.HexColor("#E0B000"),
    "D": colors.HexColor("#FB8C00"),
    "F": colors.HexColor("#B71C1C"),
    "N/A": colors.HexColor("#94A3B8"),
}

PORTRAIT = A4
LANDSCAPE = landscape(A4)
MARGIN_X = 16 * mm
MARGIN_TOP = 22 * mm
MARGIN_BOTTOM = 18 * mm
PORTRAIT_WIDTH = PORTRAIT[0] - 2 * MARGIN_X
LANDSCAPE_WIDTH = LANDSCAPE[0] - 2 * MARGIN_X

FONT = "CSans"
FONT_BOLD = "CSans-Bold"
FONT_MONO = "CSansMono"
_FONTS_READY = False

# Longest text kept in one table cell, so no row outgrows the room reserved
# above a table (see ``Builder.table_heading``).
CELL_LIMIT = 700
ROADMAP_CELL_LIMIT = 420
HEADING_STYLES = ("cs-h1", "cs-h2", "cs-h3", "cs-kicker")


# ---------------------------------------------------------------------------
# Fonts and styles
# ---------------------------------------------------------------------------


def register_fonts() -> None:
    """Register DejaVu Sans (regular, bold, oblique, mono) once."""
    global _FONTS_READY, FONT, FONT_BOLD, FONT_MONO
    if _FONTS_READY:
        return
    try:
        import matplotlib

        directory = os.path.join(matplotlib.get_data_path(), "fonts", "ttf")
        pdfmetrics.registerFont(
            TTFont("CSans", os.path.join(directory, "DejaVuSans.ttf"))
        )
        pdfmetrics.registerFont(
            TTFont("CSans-Bold", os.path.join(directory, "DejaVuSans-Bold.ttf"))
        )
        pdfmetrics.registerFont(
            TTFont("CSans-Oblique", os.path.join(directory, "DejaVuSans-Oblique.ttf"))
        )
        pdfmetrics.registerFont(
            TTFont("CSansMono", os.path.join(directory, "DejaVuSansMono.ttf"))
        )
        pdfmetrics.registerFontFamily(
            "CSans",
            normal="CSans",
            bold="CSans-Bold",
            italic="CSans-Oblique",
            boldItalic="CSans-Bold",
        )
    except Exception:  # noqa: BLE001 - fall back to the standard fonts
        logger.warning("DejaVu fonts not found; falling back to Helvetica")
        FONT, FONT_BOLD, FONT_MONO = "Helvetica", "Helvetica-Bold", "Courier"
    _FONTS_READY = True


def styles() -> dict[str, ParagraphStyle]:
    """Paragraph styles used by the renderer."""
    register_fonts()
    base = ParagraphStyle(
        "cs-body", fontName=FONT, fontSize=9.2, leading=13.4, textColor=INK_SOFT
    )
    return {
        "body": base,
        "body_ink": ParagraphStyle("cs-body-ink", parent=base, textColor=INK),
        "small": ParagraphStyle(
            "cs-small", parent=base, fontSize=7.8, leading=10.6, textColor=MUTED
        ),
        "cell": ParagraphStyle(
            "cs-cell", parent=base, fontSize=7.4, leading=9.6, textColor=INK
        ),
        "cell_head": ParagraphStyle(
            "cs-cell-head",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=7.4,
            leading=9.4,
            textColor=WHITE,
        ),
        "mono": ParagraphStyle(
            "cs-mono",
            parent=base,
            fontName=FONT_MONO,
            fontSize=7.2,
            leading=9.4,
            textColor=INK,
        ),
        "kicker": ParagraphStyle(
            "cs-kicker",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=7.6,
            leading=10,
            textColor=BRAND,
            spaceAfter=1,
            keepWithNext=1,
        ),
        "h1": ParagraphStyle(
            "cs-h1",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=18,
            leading=22,
            textColor=INK,
            spaceAfter=8,
            keepWithNext=1,
        ),
        "h2": ParagraphStyle(
            "cs-h2",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=12.4,
            leading=16,
            textColor=INK,
            spaceBefore=8,
            spaceAfter=5,
            keepWithNext=1,
        ),
        "h3": ParagraphStyle(
            "cs-h3",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=9.8,
            leading=13,
            textColor=BRAND_DARK,
            spaceBefore=5,
            spaceAfter=3,
            keepWithNext=1,
        ),
        "h2_free": ParagraphStyle(
            "cs-h2-free",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=12.4,
            leading=16,
            textColor=INK,
            spaceBefore=8,
            spaceAfter=5,
            keepWithNext=0,
        ),
        "h3_free": ParagraphStyle(
            "cs-h3-free",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=9.8,
            leading=13,
            textColor=BRAND_DARK,
            spaceBefore=5,
            spaceAfter=3,
            keepWithNext=0,
        ),
        "kpi_value": ParagraphStyle(
            "cs-kpi-value",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=17,
            leading=20,
            textColor=INK,
        ),
        "kpi_label": ParagraphStyle(
            "cs-kpi-label", parent=base, fontSize=7.4, leading=9.4, textColor=MUTED
        ),
        "cover_kicker": ParagraphStyle(
            "cs-cover-kicker",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#7EB8FF"),
        ),
        "cover_title": ParagraphStyle(
            "cs-cover-title",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=30,
            leading=36,
            textColor=WHITE,
        ),
        "cover_sub": ParagraphStyle(
            "cs-cover-sub",
            parent=base,
            fontSize=11,
            leading=16,
            textColor=colors.HexColor("#CBD5E1"),
        ),
        "cover_meta": ParagraphStyle(
            "cs-cover-meta",
            parent=base,
            fontSize=8.6,
            leading=13,
            textColor=colors.HexColor("#94A3B8"),
        ),
        "toc0": ParagraphStyle(
            "cs-toc0",
            parent=base,
            fontName=FONT_BOLD,
            fontSize=10,
            leading=17,
            textColor=INK,
            leftIndent=0,
        ),
        "toc1": ParagraphStyle(
            "cs-toc1",
            parent=base,
            fontSize=8.8,
            leading=13.5,
            textColor=INK_SOFT,
            leftIndent=14,
        ),
    }


def text(value: Any, limit: int | None = None) -> str:
    """Escape a value for a Paragraph; missing values read ``-``."""
    if value is None or value == "":
        return "-"
    if isinstance(value, float):
        value = f"{value:.1f}"
    value = str(value)
    if limit and len(value) > limit:
        value = value[: limit - 1].rstrip() + "…"
    return escape(value)


def severity_markup(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, MUTED).hexval()[2:]
    return f'<font color="#{color}">●</font> {escape(severity.capitalize())}'


def priority_markup(priority: str | None) -> str:
    if not priority or priority == "-":
        return "-"
    color = PRIORITY_COLORS.get(priority, MUTED).hexval()[2:]
    return f'<font color="#{color}"><b>{escape(priority)}</b></font>'


# ---------------------------------------------------------------------------
# Document template with layout tracking
# ---------------------------------------------------------------------------


class Gap(Spacer):
    """Vertical space that shrinks to what is left on the page.

    A plain Spacer that does not fit moves to the next page and can leave a
    page that holds nothing but space.
    """

    def wrap(self, availWidth: float, availHeight: float) -> tuple[float, float]:  # noqa: N803
        if not hasattr(self, "_full_height"):
            self._full_height = self.height
        self.height = max(0.0, min(self._full_height, availHeight))
        return availWidth, self.height


class Heading(Paragraph):
    """Section heading that becomes a bookmark and a contents entry."""

    def __init__(self, label: str, style: ParagraphStyle, level: int, key: str) -> None:
        super().__init__(escape(label), style)
        self.label = label
        self.level = level
        self.key = key


class BrandedDoc(BaseDocTemplate):
    """Document template that records bookmarks and layout statistics.

    ``meta`` holds ``title`` and ``generated`` (header and footer),
    ``period`` (footer), ``cover_note`` or ``engine_version`` (cover foot),
    and ``total_pages`` (the "Page X of Y" total of the previous pass).
    """

    def __init__(self, buffer: io.BytesIO, meta: dict[str, Any], **kwargs: Any) -> None:
        super().__init__(buffer, pagesize=PORTRAIT, **kwargs)
        self.meta = meta
        portrait_frame = Frame(
            MARGIN_X,
            MARGIN_BOTTOM,
            PORTRAIT_WIDTH,
            PORTRAIT[1] - MARGIN_TOP - MARGIN_BOTTOM,
            id="portrait",
            leftPadding=0,
            rightPadding=0,
            topPadding=0,
            bottomPadding=0,
        )
        landscape_frame = Frame(
            MARGIN_X,
            MARGIN_BOTTOM,
            LANDSCAPE_WIDTH,
            LANDSCAPE[1] - MARGIN_TOP - MARGIN_BOTTOM,
            id="landscape",
            leftPadding=0,
            rightPadding=0,
            topPadding=0,
            bottomPadding=0,
        )
        cover_frame = Frame(
            22 * mm,
            24 * mm,
            PORTRAIT[0] - 44 * mm,
            PORTRAIT[1] - 60 * mm,
            id="cover",
            leftPadding=0,
            rightPadding=0,
            topPadding=0,
            bottomPadding=0,
        )
        self.addPageTemplates(
            [
                PageTemplate(
                    "cover", [cover_frame], onPage=self._draw_cover, pagesize=PORTRAIT
                ),
                PageTemplate(
                    "portrait",
                    [portrait_frame],
                    onPage=self._draw_chrome,
                    pagesize=PORTRAIT,
                ),
                PageTemplate(
                    "landscape",
                    [landscape_frame],
                    onPage=self._draw_chrome,
                    pagesize=LANDSCAPE,
                ),
            ]
        )
        self.layout: dict[str, Any] = {}

    def beforeDocument(self) -> None:  # noqa: N802 - reportlab API
        self._content: dict[int, int] = {}
        self._last_kind: dict[int, str] = {}
        self._headings = 0
        self._bookmarks = 0
        self._pages_drawn = 0

    def handle_flowable(self, flowables: list) -> None:
        # A page that holds only space counts as empty: do not break again.
        first = flowables[0] if flowables else None
        if (
            isinstance(first, PageBreakIfNotEmpty)
            and not self._content.get(self.page)
            and (not first.nextTemplate or self._samePT(first.nextTemplate))
        ):
            del flowables[0]
            return
        super().handle_flowable(flowables)

    def afterFlowable(self, flowable: Flowable) -> None:  # noqa: N802 - reportlab API
        if isinstance(flowable, (Spacer, ActionFlowable, PageBreak, CondPageBreak)):
            return
        page = self.page
        self._content[page] = self._content.get(page, 0) + 1
        is_heading = isinstance(flowable, Heading) or (
            isinstance(flowable, Paragraph)
            and flowable.style.name.startswith(HEADING_STYLES)
        )
        self._last_kind[page] = "heading" if is_heading else "content"
        if isinstance(flowable, Heading):
            self.canv.bookmarkPage(flowable.key)
            self.canv.addOutlineEntry(
                flowable.label,
                flowable.key,
                level=flowable.level,
                closed=flowable.level > 0,
            )
            self.notify(
                "TOCEntry", (flowable.level, flowable.label, page, flowable.key)
            )
            self._headings += 1
            self._bookmarks += 1

    def _endBuild(self) -> None:  # noqa: N802 - reportlab API
        # BaseDocTemplate has no after-document hook; run ours after each pass.
        super()._endBuild()
        self.afterDocument()

    def afterDocument(self) -> None:  # noqa: N802 - local hook, see _endBuild
        pages = self._pages_drawn
        # The next build pass prints "Page X of Y" with this count.
        self.meta["printed_total"] = self.meta.get("total_pages")
        self.meta["total_pages"] = pages
        self.layout = {
            "pages": pages,
            "blank_pages": [
                page for page in range(1, pages + 1) if not self._content.get(page)
            ],
            "orphan_headings": [
                page
                for page, kind in sorted(self._last_kind.items())
                if kind == "heading"
            ],
            "toc_entries": self._headings,
            "bookmarks": self._bookmarks,
            "metadata": bool(
                self.title and self.author and self.subject and self.keywords
            ),
            "page_total_consistent": self.meta.get("printed_total") == pages,
        }

    # -- page decoration --------------------------------------------------

    def _draw_cover(self, canv: Canvas, doc: Any) -> None:
        self._pages_drawn = max(self._pages_drawn, canv.getPageNumber())
        width, height = PORTRAIT
        canv.saveState()
        canv.setFillColor(COVER_BG)
        canv.rect(0, 0, width, height, stroke=0, fill=1)
        # Layered accent bands.
        for index, (color, alpha) in enumerate(
            ((BRAND, 0.55), (VIOLET, 0.45), (TEAL, 0.35))
        ):
            canv.setFillColor(color)
            canv.setFillAlpha(alpha)
            path = canv.beginPath()
            offset = index * 34 * mm
            path.moveTo(width * 0.42 + offset, height)
            path.lineTo(width, height)
            path.lineTo(width, height * 0.58 - offset)
            path.close()
            canv.drawPath(path, stroke=0, fill=1)
        canv.setFillAlpha(1)
        canv.setFillColor(BRAND)
        canv.rect(22 * mm, height - 30 * mm, 18 * mm, 1.6 * mm, stroke=0, fill=1)
        canv.setFont(FONT_BOLD, 11)
        canv.setFillColor(WHITE)
        canv.drawString(22 * mm, height - 25 * mm, brand.name)
        self._confidential_label(canv, width - 22 * mm, 16 * mm, dark=True)
        canv.setFont(FONT, 7.6)
        canv.setFillColor(colors.HexColor("#94A3B8"))
        note = self.meta.get("cover_note") or (
            f"Report engine {self.meta.get('engine_version', '')}"
        )
        canv.drawString(22 * mm, 16 * mm, note)
        canv.restoreState()

    def _confidential_label(
        self, canv: Canvas, right: float, y: float, dark: bool = False
    ) -> None:
        label = "CONFIDENTIAL"
        canv.setFont(FONT_BOLD, 7)
        width = canv.stringWidth(label, FONT_BOLD, 7) + 8 * mm / 2
        canv.setFillColor(
            colors.HexColor("#B71C1C") if not dark else colors.HexColor("#E53935")
        )
        canv.roundRect(
            right - width, y - 1.6 * mm, width, 5 * mm, 1.4 * mm, stroke=0, fill=1
        )
        canv.setFillColor(WHITE)
        canv.drawCentredString(right - width / 2, y, label)

    def _draw_chrome(self, canv: Canvas, doc: Any) -> None:
        self._pages_drawn = max(self._pages_drawn, canv.getPageNumber())
        width, height = canv._pagesize
        canv.saveState()
        canv.setFillColor(BRAND)
        canv.rect(0, height - 3 * mm, width, 3 * mm, stroke=0, fill=1)
        canv.setFont(FONT_BOLD, 8)
        canv.setFillColor(INK)
        canv.drawString(MARGIN_X, height - 12 * mm, brand.name)
        canv.setFont(FONT, 7.8)
        canv.setFillColor(MUTED)
        title = self.meta.get("title", "")
        canv.drawString(
            MARGIN_X + canv.stringWidth(brand.name, FONT_BOLD, 8) + 4 * mm,
            height - 12 * mm,
            title,
        )
        self._confidential_label(canv, width - MARGIN_X, height - 12 * mm)
        canv.setStrokeColor(LINE)
        canv.setLineWidth(0.6)
        canv.line(MARGIN_X, height - 15 * mm, width - MARGIN_X, height - 15 * mm)
        canv.line(MARGIN_X, 13 * mm, width - MARGIN_X, 13 * mm)
        canv.setFont(FONT, 7.6)
        canv.setFillColor(MUTED)
        parts = [f"Generated {self.meta.get('generated', '')}"]
        if self.meta.get("period"):
            parts.append(self.meta["period"])
        parts.append("Confidential: for the recipient organization only")
        canv.drawString(MARGIN_X, 9 * mm, "  ·  ".join(parts))
        total = self.meta.get("total_pages")
        number = canv.getPageNumber()
        canv.drawRightString(
            width - MARGIN_X,
            9 * mm,
            f"Page {number} of {total}" if total else f"Page {number}",
        )
        canv.restoreState()


# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------


class Builder:
    """Story builder with section numbering and shared styles."""

    def __init__(self) -> None:
        self.s = styles()
        self.sections = 0
        self.keys = 0

    def key(self) -> str:
        self.keys += 1
        return f"sec{self.keys}"

    def h1(self, label: str, kicker: str | None = None) -> list:
        self.sections += 1
        items: list = []
        if kicker:
            items.append(Paragraph(escape(kicker.upper()), self.s["kicker"]))
        items.append(Heading(label, self.s["h1"], 0, self.key()))
        return items

    def h2(self, label: str, bookmark: bool = True) -> Flowable:
        if bookmark:
            return Heading(label, self.s["h2"], 1, self.key())
        return Paragraph(escape(label), self.s["h2"])

    def h3(self, label: str) -> Paragraph:
        return Paragraph(escape(label), self.s["h3"])

    def table_heading(
        self,
        label: str,
        *,
        level: int = 2,
        bookmark: bool = True,
        room: float = 45 * mm,
    ) -> list:
        """Heading placed right before a long table.

        A long table cannot be kept with its heading without pushing the
        whole table to the next page, so the heading instead asks for
        ``room`` (enough for the header and the first rows) and starts a new
        page when less is left.
        """
        style = self.s["h2_free"] if level == 2 else self.s["h3_free"]
        if level == 2 and bookmark:
            heading: Flowable = Heading(label, style, 1, self.key())
        else:
            heading = Paragraph(escape(label), style)
        return [CondPageBreak(room), heading]

    def para(self, value: str, style: str = "body") -> Paragraph:
        return Paragraph(value, self.s[style])

    def callout(
        self, markup: str, tone: colors.Color = BRAND, width: float = PORTRAIT_WIDTH
    ) -> Table:
        table = Table([[Paragraph(markup, self.s["body_ink"])]], colWidths=[width])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), PANEL),
                    ("LINEBEFORE", (0, 0), (0, -1), 2.4, tone),
                    ("LEFTPADDING", (0, 0), (-1, -1), 9),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ]
            )
        )
        return table

    def table(
        self,
        columns: list[tuple[str, str, float]],
        rows: list[dict[str, Any]],
        *,
        markup: dict[str, Any] | None = None,
        width: float = PORTRAIT_WIDTH,
        header_color: colors.Color = INK,
        cell_limit: int = CELL_LIMIT,
    ) -> LongTable:
        """Long table with a repeating header row.

        Args:
            columns: ``(field, header, relative width)``.
            rows: Row mappings.
            markup: Field to ``callable(value, row) -> markup`` for rich cells.
            width: Total width.
            header_color: Header background.
        """
        total = sum(weight for _, _, weight in columns) or 1.0
        widths = [width * weight / total for _, _, weight in columns]
        markup = markup or {}
        data = [
            [Paragraph(escape(header), self.s["cell_head"]) for _, header, _ in columns]
        ]
        for row in rows:
            cells = []
            for field, _, _ in columns:
                value = row.get(field)
                if field in markup:
                    cells.append(Paragraph(markup[field](value, row), self.s["cell"]))
                else:
                    cells.append(Paragraph(text(value, cell_limit), self.s["cell"]))
            data.append(cells)
        table = LongTable(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), header_color),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3.2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.6),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ]
        for index in range(1, len(data)):
            if index % 2 == 0:
                style.append(("BACKGROUND", (0, index), (-1, index), PANEL))
        table.setStyle(TableStyle(style))
        return table

    def kpis(
        self,
        items: list[tuple[str, Any]],
        columns: int = 4,
        width: float = PORTRAIT_WIDTH,
    ) -> Table:
        """Grid of KPI tiles; ``None`` values read ``Not assessed``."""
        cells = []
        for label, value in items:
            if value is None:
                shown = f'<font size="10">{NOT_ASSESSED}</font>'
            elif isinstance(value, float):
                shown = f"{value:.1f}"
            else:
                shown = escape(str(value))
            cells.append(
                [
                    Paragraph(shown, self.s["kpi_value"]),
                    Paragraph(escape(label), self.s["kpi_label"]),
                ]
            )
        while len(cells) % columns:
            cells.append(["", ""])
        grid = []
        tile_width = (width - (columns - 1) * 4 * mm) / columns
        for start in range(0, len(cells), columns):
            row = []
            for cell in cells[start : start + columns]:
                tile = Table([[cell[0]], [cell[1]]], colWidths=[tile_width])
                tile.setStyle(
                    TableStyle(
                        [
                            (
                                "BACKGROUND",
                                (0, 0),
                                (-1, -1),
                                PANEL if cell[0] != "" else WHITE,
                            ),
                            (
                                "LINEABOVE",
                                (0, 0),
                                (-1, 0),
                                1.6,
                                BRAND if cell[0] != "" else WHITE,
                            ),
                            ("LEFTPADDING", (0, 0), (-1, -1), 7),
                            ("TOPPADDING", (0, 0), (-1, 0), 6),
                            ("BOTTOMPADDING", (0, -1), (-1, -1), 6),
                        ]
                    )
                )
                row.append(tile)
            grid.append(row)
        table = Table(grid, colWidths=[tile_width + 4 * mm] * columns, hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4 * mm),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4 * mm),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        return table

    def bullets(self, items: list[str], style: str = "body") -> list:
        return [
            Paragraph(f"{escape(item)}", self.s[style], bulletText="•")
            for item in items
            if item
        ]


# ---------------------------------------------------------------------------
# Charts (vector drawings)
# ---------------------------------------------------------------------------


def score_ring(score: float | None, grade: str, size: float = 34 * mm) -> Drawing:
    """Score donut with the grade inside."""
    register_fonts()
    drawing = Drawing(size, size)
    center = size / 2
    radius = size / 2 - 1
    thickness = size * 0.13
    drawing.add(Circle(center, center, radius, fillColor=LINE, strokeColor=None))
    color = GRADE_COLORS.get(grade, GRADE_COLORS["N/A"])
    if score is not None and score > 0:
        extent = 360.0 * min(score, 100.0) / 100.0
        if extent >= 359.9:
            drawing.add(
                Circle(center, center, radius, fillColor=color, strokeColor=None)
            )
        else:
            drawing.add(
                Wedge(
                    center,
                    center,
                    radius,
                    90 - extent,
                    90,
                    fillColor=color,
                    strokeColor=None,
                )
            )
    drawing.add(
        Circle(center, center, radius - thickness, fillColor=WHITE, strokeColor=None)
    )
    label = f"{score:.0f}" if score is not None else "–"
    drawing.add(
        String(
            center,
            center + 1,
            label,
            fontName=FONT_BOLD,
            fontSize=size * 0.27,
            fillColor=INK,
            textAnchor="middle",
        )
    )
    drawing.add(
        String(
            center,
            center - size * 0.17,
            f"Grade {grade}",
            fontName=FONT,
            fontSize=size * 0.1,
            fillColor=MUTED,
            textAnchor="middle",
        )
    )
    return drawing


def hbar_chart(
    items: list[tuple[str, int, colors.Color]], width: float, bar: float = 5.2 * mm
) -> Drawing:
    """Labelled horizontal bars."""
    register_fonts()
    label_width = width * 0.34
    value_width = 16 * mm
    track = width - label_width - value_width
    height = max(bar, len(items) * (bar + 2.2 * mm))
    drawing = Drawing(width, height)
    peak = max([value for _, value, _ in items] + [1])
    for index, (label, value, color) in enumerate(items):
        y = height - (index + 1) * (bar + 2.2 * mm) + 2.2 * mm
        shown = label if len(label) <= 34 else label[:33] + "…"
        drawing.add(
            String(
                0, y + bar * 0.3, shown, fontName=FONT, fontSize=7.4, fillColor=INK_SOFT
            )
        )
        drawing.add(Rect(label_width, y, track, bar, fillColor=PANEL, strokeColor=None))
        if value:
            drawing.add(
                Rect(
                    label_width,
                    y,
                    max(1.5, track * value / peak),
                    bar,
                    fillColor=color,
                    strokeColor=None,
                )
            )
        drawing.add(
            String(
                width,
                y + bar * 0.3,
                f"{value:,}",
                fontName=FONT_BOLD,
                fontSize=7.6,
                fillColor=INK,
                textAnchor="end",
            )
        )
    return drawing


def severity_strip(by_severity: dict[str, int], width: float) -> Drawing:
    """One stacked bar of open findings by severity, with a legend."""
    register_fonts()
    drawing = Drawing(width, 16 * mm)
    total = sum(by_severity.get(sev, 0) for sev in SEVERITY_ORDER)
    x = 0.0
    if total:
        for severity in SEVERITY_ORDER:
            value = by_severity.get(severity, 0)
            if not value:
                continue
            segment = width * value / total
            drawing.add(
                Rect(
                    x,
                    9 * mm,
                    segment,
                    5 * mm,
                    fillColor=SEVERITY_COLORS[severity],
                    strokeColor=WHITE,
                    strokeWidth=0.6,
                )
            )
            x += segment
    else:
        drawing.add(Rect(0, 9 * mm, width, 5 * mm, fillColor=LINE, strokeColor=None))
    x = 0.0
    for severity in SEVERITY_ORDER:
        drawing.add(
            Rect(
                x,
                2.4 * mm,
                2.6 * mm,
                2.6 * mm,
                fillColor=SEVERITY_COLORS[severity],
                strokeColor=None,
            )
        )
        label = f"{severity.capitalize()} {by_severity.get(severity, 0):,}"
        drawing.add(
            String(
                x + 3.8 * mm,
                2.8 * mm,
                label,
                fontName=FONT,
                fontSize=7.2,
                fillColor=INK_SOFT,
            )
        )
        x += width / len(SEVERITY_ORDER)
    return drawing


def trend_chart(
    points: list[dict[str, Any]],
    width: float,
    height: float = 58 * mm,
    comparable_note: bool = True,
) -> Drawing:
    """Open findings over time; hollow markers are not like-for-like.

    Points carry ``date``, ``total``, ``critical``, ``high``, and
    ``comparable``. ``comparable_note`` adds the legend entry that explains
    hollow markers.
    """
    register_fonts()
    drawing = Drawing(width, height)
    left, bottom, top = 12 * mm, 9 * mm, 6 * mm
    plot_w = width - left - 4 * mm
    plot_h = height - bottom - top
    series = [
        ("Open findings", [point["total"] for point in points], BRAND),
        (
            "Critical + high",
            [point["critical"] + point["high"] for point in points],
            SEVERITY_COLORS["critical"],
        ),
    ]
    peak = max([max(values) for _, values, _ in series if values] + [1])
    step = max(1, len(points) - 1)
    for tick in range(5):
        y = bottom + plot_h * tick / 4
        drawing.add(Line(left, y, left + plot_w, y, strokeColor=LINE, strokeWidth=0.5))
        drawing.add(
            String(
                left - 2,
                y - 2.4,
                f"{round(peak * tick / 4):,}",
                fontName=FONT,
                fontSize=6.6,
                fillColor=MUTED,
                textAnchor="end",
            )
        )
    label_every = max(1, len(points) // 6)
    for index, point in enumerate(points):
        x = left + plot_w * index / step if len(points) > 1 else left + plot_w / 2
        if index % label_every == 0 or index == len(points) - 1:
            drawing.add(
                String(
                    x,
                    bottom - 6.5 * mm / 1.6,
                    point["date"][5:],
                    fontName=FONT,
                    fontSize=6.6,
                    fillColor=MUTED,
                    textAnchor="middle",
                )
            )
    for _, values, color in series:
        coords: list[float] = []
        for index, value in enumerate(values):
            x = left + plot_w * index / step if len(values) > 1 else left + plot_w / 2
            coords += [x, bottom + plot_h * value / peak]
        if len(values) > 1:
            drawing.add(PolyLine(coords, strokeColor=color, strokeWidth=1.6))
        for index in range(len(values)):
            comparable = points[index]["comparable"]
            drawing.add(
                Circle(
                    coords[index * 2],
                    coords[index * 2 + 1],
                    1.5,
                    fillColor=color if comparable else WHITE,
                    strokeColor=color,
                    strokeWidth=0.9,
                )
            )
    x = left
    for label, _, color in series:
        drawing.add(
            Rect(
                x, height - 4 * mm, 3 * mm, 1.6 * mm, fillColor=color, strokeColor=None
            )
        )
        drawing.add(
            String(
                x + 4 * mm,
                height - 4.2 * mm,
                label,
                fontName=FONT,
                fontSize=7,
                fillColor=INK_SOFT,
            )
        )
        x += 34 * mm
    if comparable_note:
        drawing.add(
            String(
                x,
                height - 4.2 * mm,
                "○ coverage differs from period end",
                fontName=FONT,
                fontSize=7,
                fillColor=MUTED,
            )
        )
    return drawing


def pass_bar(pct: float | None, width: float = 30 * mm) -> Drawing:
    drawing = Drawing(width, 3.4 * mm)
    drawing.add(Rect(0, 0.4 * mm, width, 2.6 * mm, fillColor=LINE, strokeColor=None))
    if pct is not None:
        color = TEAL if pct >= 80 else BRAND if pct >= 60 else SEVERITY_COLORS["medium"]
        drawing.add(
            Rect(
                0,
                0.4 * mm,
                width * pct / 100.0,
                2.6 * mm,
                fillColor=color,
                strokeColor=None,
            )
        )
    return drawing


# ---------------------------------------------------------------------------
# Shared page blocks
# ---------------------------------------------------------------------------


def cover_block(
    b: Builder,
    kicker: str,
    title: str,
    subtitle: str,
    facts: list[tuple[str, str]],
) -> list:
    """Flowables of the dark cover page: kicker, title, subtitle, facts."""
    items: list = [
        Gap(1, 62 * mm),
        Paragraph(escape(kicker.upper()), b.s["cover_kicker"]),
        Gap(1, 4 * mm),
        Paragraph(escape(title), b.s["cover_title"]),
        Gap(1, 5 * mm),
        Paragraph(escape(subtitle), b.s["cover_sub"]),
        Gap(1, 16 * mm),
    ]
    rows = [
        [
            Paragraph(escape(label.upper()), b.s["cover_meta"]),
            Paragraph(
                f'<font color="#FFFFFF">{escape(value)}</font>', b.s["cover_sub"]
            ),
        ]
        for label, value in facts
    ]
    table = Table(rows, colWidths=[42 * mm, 110 * mm], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#1E293B")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    items.append(table)
    return items


def contents_block(b: Builder) -> list:
    """Contents page: clickable entries for every bookmarked heading."""
    toc = TableOfContents(dotsMinLevel=0)
    toc.levelStyles = [b.s["toc0"], b.s["toc1"]]
    # A plain heading: the contents page does not list itself.
    return [Paragraph("Contents", b.s["h1"]), toc]


def grade_markup(grade: Any) -> str:
    """Grade letter in its grade colour."""
    color = GRADE_COLORS.get(str(grade), MUTED).hexval()[2:]
    return f'<font color="#{color}"><b>{escape(str(grade))}</b></font>'


def ring_head(
    ring: Drawing, side: Any, ring_width: float = 40 * mm, width: float = PORTRAIT_WIDTH
) -> Table:
    """Score ring on the left, ``side`` (flowable or list) on the right."""
    head = Table([[ring, side]], colWidths=[ring_width, width - ring_width])
    head.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return head
