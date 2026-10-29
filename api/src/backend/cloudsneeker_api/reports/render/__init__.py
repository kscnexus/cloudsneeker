"""Report renderers keyed by output format."""

from __future__ import annotations

from collections.abc import Callable

from cloudsneeker_api.reports.catalog import (
    FORMAT_CSV,
    FORMAT_JSON,
    FORMAT_PDF,
    FORMAT_XLSX,
    ReportParamsError,
)
from cloudsneeker_api.reports.schema import ReportData

Renderer = Callable[[ReportData], bytes]


def get_renderer(fmt: str) -> Renderer:
    """Return the renderer of an output format.

    PDF imports reportlab / matplotlib lazily so API processes that never
    render a PDF do not load them.

    Args:
        fmt: ``pdf``, ``xlsx``, ``csv``, or ``json``.

    Returns:
        ``render(data) -> bytes``.

    Raises:
        ReportParamsError: The format is unknown.
    """
    if fmt == FORMAT_PDF:
        from cloudsneeker_api.reports.render.pdf import render_pdf

        return render_pdf
    from cloudsneeker_api.reports.render import tabular

    renderers = {
        FORMAT_XLSX: tabular.render_xlsx,
        FORMAT_CSV: tabular.render_csv,
        FORMAT_JSON: tabular.render_json,
    }
    try:
        return renderers[fmt]
    except KeyError as exc:
        raise ReportParamsError(f"Unknown format: {fmt}") from exc
