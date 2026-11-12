"""Focused report PDFs use the shared assessment design.

Set ``CS_REPORT_SAMPLES_DIR`` to also write the sample PDFs there; the CI
workflow renders them to PNG images for visual inspection.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from cloudsneeker_api.reports.assessment import render_pdf as assessment_pdf
from cloudsneeker_api.reports.render import get_renderer, pdf_style
from cloudsneeker_api.reports.render.pdf import (
    NOT_SCORED,
    REPORT_KICKERS,
    build_pdf,
    story,
)
from cloudsneeker_api.reports.schema import ReportFilters
from cloudsneeker_api.tests.test_reports_render import _exceptions_report, _report
from reportlab.platypus import LongTable, Paragraph, Table

FOCUSED_TYPES = sorted(REPORT_KICKERS)


def _texts(flowables: list) -> list[str]:
    """Plain text of every paragraph, including those inside tables."""
    found: list[str] = []
    for item in flowables:
        if isinstance(item, Paragraph):
            found.append(item.getPlainText())
        elif isinstance(item, Table):
            for row in item._cellvalues:
                for cell in row:
                    found += _texts(cell if isinstance(cell, list) else [cell])
        elif isinstance(item, list):
            found += _texts(item)
    return found


def _typed(report_type: str, **kwargs):
    data = _report(**kwargs)
    data.report_type = report_type
    data.title = f"{report_type.replace('_', ' ').title()} Report"
    return data


def _write_sample(name: str, pdf: bytes) -> None:
    target = os.environ.get("CS_REPORT_SAMPLES_DIR")
    if target:
        Path(target).mkdir(parents=True, exist_ok=True)
        (Path(target) / f"focused-{name}.pdf").write_bytes(pdf)


def _assert_clean(layout: dict) -> None:
    assert layout["blank_pages"] == []
    assert layout["orphan_headings"] == []
    assert layout["bookmarks"] == layout["toc_entries"]
    assert layout["metadata"]
    assert layout["page_total_consistent"]


class TestSharedDesign:
    def test_assessment_and_focused_reports_share_one_template(self):
        assert assessment_pdf.AssessmentDoc is pdf_style.BrandedDoc
        assert assessment_pdf.styles is pdf_style.styles
        assert assessment_pdf.Builder is pdf_style.Builder

    @pytest.mark.parametrize("report_type", FOCUSED_TYPES)
    def test_every_type_renders_in_the_new_style(self, report_type):
        data = _typed(report_type)
        pdf, layout = build_pdf(data)
        assert pdf.startswith(b"%PDF")
        assert b"FontFile2" in pdf  # embedded DejaVu (shared fonts)
        assert b"/Outlines" in pdf  # bookmarks
        assert b"/Annots" in pdf  # clickable contents
        _assert_clean(layout)
        assert layout["toc_entries"] >= 6
        texts = _texts(story(data))
        assert REPORT_KICKERS[report_type].upper() in texts
        assert data.title in texts
        assert "CLASSIFICATION" in texts
        for heading in (
            "Executive summary",
            "Risk distribution",
            "Trend",
            "Top risks",
            "Coverage and sources",
            "Compliance posture",
            "Recommended next actions",
            "Detailed results",
            "Appendix: methodology",
        ):
            assert heading in texts, heading
        # Same paragraph styles as the assessments.
        style_names = {
            item.style.name for item in story(data) if isinstance(item, Paragraph)
        }
        assert {"cs-h1", "cs-kicker", "cs-cover-title"} <= style_names
        _write_sample(report_type, get_renderer("pdf")(data))

    def test_kpis_severity_and_status_totals_are_kept(self):
        texts = _texts(story(_report()))
        assert "Failed findings" in texts and "12" in texts
        assert "Results by status" in texts
        assert "Manual review" in texts
        assert "Open findings by severity" in texts

    def test_report_without_score_reads_not_scored(self):
        data = _exceptions_report()
        texts = _texts(story(data))
        assert NOT_SCORED in " ".join(texts)
        pdf, layout = build_pdf(data)
        _assert_clean(layout)
        _write_sample("exceptions", pdf)


class TestEmptyState:
    @pytest.mark.parametrize("report_type", FOCUSED_TYPES)
    def test_empty_data_renders_the_empty_state(self, report_type):
        data = _typed(report_type, empty=True)
        pdf, layout = build_pdf(data)
        assert pdf.startswith(b"%PDF")
        _assert_clean(layout)
        texts = " ".join(_texts(story(data)))
        assert "Nothing to report." in texts
        assert data.empty_state in texts
        assert "Detailed results" not in texts
        assert layout["toc_entries"] == 2  # summary and methodology
        if report_type == "cloud_posture":
            _write_sample("empty", pdf)


class TestTables:
    def test_long_table_spans_pages_with_repeated_header(self):
        short_pdf, short = build_pdf(_report(rows=3))
        long_data = _report(rows=300)
        long_pdf, long = build_pdf(long_data)
        _assert_clean(long)
        assert long["pages"] >= short["pages"] + 3
        tables = [item for item in story(long_data) if isinstance(item, LongTable)]
        findings = max(tables, key=lambda table: len(table._cellvalues))
        assert len(findings._cellvalues) == 301  # header + rows
        assert findings.repeatRows == 1
        assert len(long_pdf) < 2_000_000
        _write_sample("long-table", long_pdf)

    def test_rows_are_bounded_with_a_note(self, monkeypatch):
        monkeypatch.setenv("REPORT_PDF_MAX_ROWS", "2")
        texts = " ".join(_texts(story(_report(rows=10))))
        assert "Showing the first 2 of 12 rows." in texts

    def test_status_scope_is_printed(self):
        data = _report()
        data.filters = ReportFilters(status_scope="muted")
        texts = _texts(story(data))
        assert "FINDING STATUS" in texts
        assert "Muted" in texts
        assert any(t.startswith("Finding status scope: Muted.") for t in texts)

    def test_markup_in_values_is_escaped(self):
        data = _report()
        pdf, layout = build_pdf(data)
        _assert_clean(layout)
        assert "Bucket <public> & open" in _texts(story(data))
