"""Assessment PDF renderer.

A4 portrait pages, landscape pages for the wide roadmap and appendix tables,
a dark cover, a clickable contents page, PDF bookmarks, document metadata, a
Confidential header label, and "Page X of Y" footers. Fonts are DejaVu Sans
(shipped with matplotlib), embedded as TrueType so any Unicode text prints.

Layout statistics (pages, pages without content, headings left alone at the
bottom of a page, contents entries, bookmarks) are recorded during the final
build pass and handed to the quality engine.
"""

from __future__ import annotations

import io
import logging
import os
from datetime import datetime
from typing import Any
from xml.sax.saxutils import escape

from cloudsneeker_api.brand import brand, pdf_author, pdf_creator
from cloudsneeker_api.reports.assessment.model import NOT_ASSESSED
from cloudsneeker_api.reports.schema import SEVERITY_ORDER, ReportData
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
    KeepTogether,
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


class AssessmentDoc(BaseDocTemplate):
    """Document template that records bookmarks and layout statistics."""

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
        canv.drawString(
            22 * mm, 16 * mm, f"Report engine {self.meta.get('engine_version', '')}"
        )
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
        canv.drawString(
            MARGIN_X,
            9 * mm,
            f"Generated {self.meta.get('generated', '')}  ·  {self.meta.get('period', '')}  ·  "
            "Confidential: for the recipient organization only",
        )
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
    points: list[dict[str, Any]], width: float, height: float = 58 * mm
) -> Drawing:
    """Open findings over time; hollow markers are not like-for-like."""
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
    items = [
        Gap(1, 62 * mm),
        Paragraph("SECURITY ASSESSMENT REPORT", b.s["cover_kicker"]),
        Gap(1, 4 * mm),
        Paragraph(escape(meta["title"]), b.s["cover_title"]),
        Gap(1, 5 * mm),
        Paragraph(escape(" · ".join(meta.get("areas") or [])), b.s["cover_sub"]),
        Gap(1, 16 * mm),
    ]
    grade = summary.get("grade") or "N/A"
    score_text = f"{score:.0f}/100" if score is not None else NOT_ASSESSED
    facts = [
        ("Security score", f"{score_text}  ·  Grade {grade}"),
        ("Assessment period", meta["period"]["label"]),
        ("Sources in scope", f"{len(providers)} provider(s) / target(s)"),
        ("Generated", _fmt_date(meta.get("generated_at"))),
        ("Classification", "Confidential"),
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


def contents(b: Builder) -> list:
    toc = TableOfContents(dotsMinLevel=0)
    toc.levelStyles = [b.s["toc0"], b.s["toc1"]]
    # A plain heading: the contents page does not list itself.
    return [Paragraph("Contents", b.s["h1"]), toc]


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
        items.append(
            KeepTogether([b.h2(title, bookmark=False), chart, Gap(1, 3 * mm)])
        )
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
