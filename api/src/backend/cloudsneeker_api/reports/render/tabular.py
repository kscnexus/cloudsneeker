"""XLSX, CSV, and JSON renderers."""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

from cloudsneeker_api.brand import brand
from cloudsneeker_api.reports.schema import SEVERITY_ORDER, ReportData, ReportTable

# Excel limits: 31-character sheet names without []:*?/\ and 1,048,576 rows.
_SHEET_NAME_INVALID = re.compile(r"[\[\]:*?/\\]")
XLSX_MAX_ROWS = 1_048_575
# Cells that start with these characters are evaluated as formulas by Excel.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

SEVERITY_FILLS: dict[str, str] = {
    "critical": "#F8D7DA",
    "high": "#FDE2E1",
    "medium": "#FFE8CC",
    "low": "#FFF8C5",
    "informational": "#ECEFF1",
}

# JSON payload bound per detail table; full lists live in the exports.
JSON_TABLE_ROWS = 500


def _cell(value: Any) -> Any:
    """Return a spreadsheet-safe cell value (no formula injection)."""
    if value is None:
        return ""
    if isinstance(value, (int, float, bool)):
        return value
    text = str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return f"'{text}"
    return text


def sheet_name(title: str, used: set[str]) -> str:
    """Return a unique, Excel-valid sheet name for ``title``."""
    base = _SHEET_NAME_INVALID.sub(" ", title).strip()[:31] or "Sheet"
    name = base
    counter = 2
    while name.lower() in used:
        suffix = f" ({counter})"
        name = f"{base[: 31 - len(suffix)]}{suffix}"
        counter += 1
    used.add(name.lower())
    return name


def render_xlsx(data: ReportData) -> bytes:
    """Render a summary sheet plus one sheet per detail table.

    Args:
        data: Assembled report data.

    Returns:
        XLSX workbook bytes.
    """
    import xlsxwriter

    buffer = io.BytesIO()
    workbook = xlsxwriter.Workbook(
        buffer, {"in_memory": True, "strings_to_formulas": False, "strings_to_urls": False}
    )
    workbook.set_properties(
        {"title": data.title, "author": brand.vendor, "company": brand.vendor}
    )
    title_fmt = workbook.add_format({"bold": True, "font_size": 16})
    header_fmt = workbook.add_format(
        {"bold": True, "font_color": "#FFFFFF", "bg_color": "#1A4D80", "border": 1}
    )
    label_fmt = workbook.add_format({"bold": True, "bg_color": "#E8F0FA", "border": 1})
    value_fmt = workbook.add_format({"border": 1, "text_wrap": True, "valign": "top"})
    severity_fmts = {
        severity: workbook.add_format({"bg_color": color, "border": 1})
        for severity, color in SEVERITY_FILLS.items()
    }
    used: set[str] = set()

    summary = workbook.add_worksheet(sheet_name("Summary", used))
    summary.set_column(0, 0, 32)
    summary.set_column(1, 1, 80)
    summary.write(0, 0, _cell(data.title), title_fmt)
    row = 2
    overview = [
        ("Product", brand.name),
        ("Generated", data.generated_at.strftime("%Y-%m-%d %H:%M UTC")),
        ("Headline", data.headline),
        ("Grade", data.grade),
        ("Score", data.score if data.score is not None else "N/A"),
    ]
    overview += [(key.replace("_", " ").capitalize(), value) for key, value in data.kpis.items()]
    overview += [
        (f"Open {severity}", data.severity_totals.get(severity, 0))
        for severity in SEVERITY_ORDER
    ]
    for key, value in data.filters.to_dict().items():
        if value:
            overview.append((f"Filter: {key}", ", ".join(value) if isinstance(value, list) else value))
    for label, value in overview:
        summary.write(row, 0, _cell(label), label_fmt)
        summary.write(row, 1, _cell(value), value_fmt)
        row += 1

    if data.remediation:
        row += 1
        summary.write(row, 0, "Recommended next actions", header_fmt)
        summary.write(row, 1, "", header_fmt)
        row += 1
        for item in data.remediation:
            summary.write(row, 0, _cell(item.get("priority")), label_fmt)
            summary.write(row, 1, _cell(item.get("action")), value_fmt)
            row += 1

    extra_tables = list(data.tables)
    if data.sources:
        fields = list(data.sources[0].keys())
        extra_tables.append(
            ReportTable(
                key="sources",
                title="Sources",
                columns=[(field, field.replace("_", " ").capitalize()) for field in fields],
                rows=data.sources,
                total=len(data.sources),
            )
        )
    if data.trend:
        extra_tables.append(
            ReportTable(
                key="trend",
                title="Trend",
                columns=[
                    ("date", "Date"),
                    ("fail", "Open"),
                    ("pass", "Passed"),
                    ("critical", "Critical"),
                    ("high", "High"),
                ],
                rows=data.trend,
                total=len(data.trend),
            )
        )

    for table in extra_tables:
        sheet = workbook.add_worksheet(sheet_name(table.title, used))
        for col, (_, header) in enumerate(table.columns):
            sheet.write(0, col, header, header_fmt)
            sheet.set_column(col, col, 40 if col and _is_wide(table.columns[col][0]) else 18)
        rows = table.rows[:XLSX_MAX_ROWS]
        severity_col = next(
            (index for index, (field, _) in enumerate(table.columns) if field == "severity"),
            None,
        )
        for row_index, item in enumerate(rows, start=1):
            for col, (field, _) in enumerate(table.columns):
                value = item.get(field)
                fmt = None
                if col == severity_col:
                    fmt = severity_fmts.get(str(value))
                sheet.write(row_index, col, _cell(value), fmt)
        last_row = max(len(rows), 1)
        sheet.autofilter(0, 0, last_row, max(len(table.columns) - 1, 0))
        sheet.freeze_panes(1, 0)
        if table.truncated or len(rows) < table.total:
            sheet.write(
                last_row + 2,
                0,
                f"Showing {len(rows)} of {table.total} rows (export bound).",
            )

    workbook.close()
    return buffer.getvalue()


def _is_wide(field: str) -> bool:
    return field in {"title", "detail", "description", "remediation", "action", "impact"}


def render_csv(data: ReportData) -> bytes:
    """Render the main detail table as CSV (UTF-8 with BOM for Excel).

    The ``findings`` / ``requirements`` / ``policies`` table is used when
    present, otherwise the first table. An empty report yields a header-only
    file with the empty-state message as a comment row.

    Args:
        data: Assembled report data.

    Returns:
        CSV bytes.
    """
    table = _primary_table(data)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    if table is None:
        writer.writerow(["message"])
        writer.writerow([_cell(data.empty_state or data.headline)])
    else:
        writer.writerow([header for _, header in table.columns])
        for item in table.rows:
            writer.writerow([_cell(item.get(field)) for field, _ in table.columns])
    return ("﻿" + buffer.getvalue()).encode("utf-8")


def _primary_table(data: ReportData) -> ReportTable | None:
    for key in ("findings", "requirements", "policies"):
        for table in data.tables:
            if table.key == key:
                return table
    return data.tables[0] if data.tables else None


def render_json(data: ReportData) -> bytes:
    """Render the in-app report payload (detail tables bounded).

    Args:
        data: Assembled report data.

    Returns:
        UTF-8 JSON bytes.
    """
    return json.dumps(
        data.to_dict(table_row_limit=JSON_TABLE_ROWS), ensure_ascii=False
    ).encode("utf-8")
