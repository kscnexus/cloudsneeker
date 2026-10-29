"""Renderers produce valid, non-empty PDF / XLSX / CSV / JSON bytes."""

from __future__ import annotations

import io
import json
import zipfile
from datetime import UTC, datetime

import pytest
from cloudsneeker_api.reports.catalog import ReportParamsError
from cloudsneeker_api.reports.data.sast import sast_row
from cloudsneeker_api.reports.data.sca import sca_row
from cloudsneeker_api.reports.data.secrets import secret_row
from cloudsneeker_api.reports.render import get_renderer
from cloudsneeker_api.reports.render.tabular import (
    JSON_TABLE_ROWS,
    _cell,
    render_csv,
    render_json,
    render_xlsx,
    sheet_name,
)
from cloudsneeker_api.reports.schema import ReportData, ReportFilters, ReportTable


def _report(*, empty: bool = False, rows: int = 3) -> ReportData:
    data = ReportData(
        report_type="cloud_posture",
        title="Cloud Posture Report",
        generated_at=datetime(2026, 10, 29, 12, 0, tzinfo=UTC),
        filters=ReportFilters(severity_floor="low"),
    )
    if empty:
        data.empty_state = "No completed cloud scans in scope."
        data.headline = data.empty_state
        return data
    data.headline = "12 open cloud findings, 3 of them critical or high. Grade C."
    data.score = 72.5
    data.grade = "C"
    data.kpis = {"failed_findings": 12, "passed_findings": 40, "critical": 1}
    data.severity_totals = {
        "critical": 1,
        "high": 2,
        "medium": 5,
        "low": 4,
        "informational": 0,
    }
    data.status_totals = {"pass": 40, "fail": 12, "muted": 1, "manual": 0}
    data.trend = [
        {"date": "2026-10-27", "fail": 15, "pass": 38, "critical": 2, "high": 3},
        {"date": "2026-10-28", "fail": 12, "pass": 40, "critical": 1, "high": 2},
    ]
    data.top_risks = [
        {
            "check_id": "iam_root_mfa_enabled",
            "title": "Root account has MFA <enabled>",
            "severity": "critical",
            "findings": 1,
            "resources": 1,
            "service": "iam",
            "impact": "Account takeover & data loss.",
            "remediation": "Enable MFA on the root account.",
        }
    ]
    data.sources = [
        {
            "scan_id": "s1",
            "provider_id": "p1",
            "provider": "prod",
            "provider_type": "aws",
            "mode": "aws",
            "completed_at": datetime(2026, 10, 28, tzinfo=UTC),
            "pass": 40,
            "fail": 12,
            "critical": 1,
            "high": 2,
            "medium": 5,
            "low": 4,
            "informational": 0,
        }
    ]
    data.compliance = [
        {"compliance_id": "cis_2.0_aws", "passed": 30, "failed": 10, "manual": 2, "total": 42, "pass_pct": 75.0},
        {"compliance_id": "iso27001_2022_aws", "passed": 0, "failed": 0, "manual": 5, "total": 5, "pass_pct": None},
    ]
    data.remediation = [
        {
            "priority": 1,
            "action": "Enable MFA on the root account.",
            "check_id": "iam_root_mfa_enabled",
            "title": "Root MFA",
            "severity": "critical",
            "resources": 1,
        }
    ]
    data.tables = [
        ReportTable(
            key="top_risks",
            title="Top risks",
            columns=[("severity", "Severity"), ("title", "Risk")],
            rows=data.top_risks,
            total=1,
        ),
        ReportTable(
            key="findings",
            title="Failed findings",
            columns=[
                ("severity", "Severity"),
                ("check_id", "Check"),
                ("title", "Title"),
                ("detail", "Detail"),
            ],
            rows=[
                {
                    "severity": "high",
                    "check_id": f"check_{index}",
                    "title": "=HYPERLINK(\"http://evil\")" if index == 0 else f"Title {index}",
                    "detail": "Bucket <public> & open",
                }
                for index in range(rows)
            ],
            total=rows + 2,
            truncated=True,
        ),
    ]
    return data


class TestPdfRenderer:
    def test_renders_full_report(self):
        content = get_renderer("pdf")(_report())
        assert content.startswith(b"%PDF")
        assert len(content) > 5000

    def test_renders_empty_report(self):
        content = get_renderer("pdf")(_report(empty=True))
        assert content.startswith(b"%PDF")

    def test_single_trend_point_and_no_charts(self):
        data = _report()
        data.trend = data.trend[:1]
        data.severity_totals = {key: 0 for key in data.severity_totals}
        data.compliance = []
        assert get_renderer("pdf")(data).startswith(b"%PDF")

    def test_caps_rows(self, monkeypatch):
        monkeypatch.setenv("REPORT_PDF_MAX_ROWS", "2")
        assert get_renderer("pdf")(_report(rows=10)).startswith(b"%PDF")


class TestXlsxRenderer:
    def test_workbook_has_summary_and_detail_sheets(self):
        content = render_xlsx(_report())
        assert content.startswith(b"PK")
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            workbook = archive.read("xl/workbook.xml").decode()
            assert 'name="Summary"' in workbook
            assert 'name="Failed findings"' in workbook
            assert 'name="Top risks"' in workbook
            assert 'name="Sources"' in workbook
            assert 'name="Trend"' in workbook
            sheet = archive.read("xl/worksheets/sheet3.xml").decode()
            # Frozen header and autofilter on detail sheets.
            assert "autoFilter" in sheet
            assert 'state="frozen"' in sheet
            strings = archive.read("xl/sharedStrings.xml").decode()
            # Formula injection is neutralized.
            assert "'=HYPERLINK" in strings
            assert "<f>" not in sheet

    def test_empty_report_still_renders(self):
        assert render_xlsx(_report(empty=True)).startswith(b"PK")

    def test_sheet_names_are_valid_and_unique(self):
        used: set[str] = set()
        assert sheet_name("Findings: a/b [x]", used) == "Findings  a b  x"
        assert sheet_name("Findings  a b  x", used) == "Findings  a b  x (2)"
        long_name = sheet_name("x" * 40, used)
        assert len(long_name) == 31

    @pytest.mark.parametrize(
        "value,expected",
        [
            (None, ""),
            (5, 5),
            ("=1+1", "'=1+1"),
            ("+cmd", "'+cmd"),
            ("-2", "'-2"),
            ("@SUM", "'@SUM"),
            ("plain", "plain"),
        ],
    )
    def test_cell_escaping(self, value, expected):
        assert _cell(value) == expected


class TestCsvRenderer:
    def test_detail_rows_with_bom(self):
        content = render_csv(_report())
        assert content.startswith("﻿".encode())
        text = content.decode("utf-8-sig")
        lines = text.strip().splitlines()
        assert lines[0] == "Severity,Check,Title,Detail"
        assert len(lines) == 4
        assert "'=HYPERLINK" in text

    def test_empty_report_writes_message(self):
        text = render_csv(_report(empty=True)).decode("utf-8-sig")
        assert text.splitlines()[0] == "message"
        assert "No completed cloud scans" in text

    def test_falls_back_to_first_table(self):
        data = _report()
        data.tables = [data.tables[0]]
        text = render_csv(data).decode("utf-8-sig")
        assert text.splitlines()[0] == "Severity,Risk"


class TestJsonRenderer:
    def test_payload_round_trips_and_bounds_rows(self):
        payload = json.loads(render_json(_report(rows=JSON_TABLE_ROWS + 5)))
        assert payload["report_type"] == "cloud_posture"
        assert payload["grade"] == "C"
        findings = next(t for t in payload["tables"] if t["key"] == "findings")
        assert len(findings["rows"]) == JSON_TABLE_ROWS
        assert findings["truncated"] is True
        assert payload["sources"][0]["completed_at"].startswith("2026-10-28")


class TestRendererRegistry:
    def test_known_formats(self):
        assert get_renderer("csv") is render_csv
        assert get_renderer("xlsx") is render_xlsx
        assert get_renderer("json") is render_json

    def test_unknown_format(self):
        with pytest.raises(ReportParamsError):
            get_renderer("docx")


class TestRowBuilders:
    def _item(self, **overrides):
        item = {
            "id": "f1",
            "check_id": "CVE-2024-1",
            "severity": "high",
            "status_extended": "AKIA**** found",
            "check_metadata": {"CheckTitle": "openssl flaw"},
            "raw_result": {
                "VulnerabilityID": "CVE-2024-1",
                "PkgName": "openssl",
                "InstalledVersion": "3.0.1",
                "FixedVersion": "3.0.8",
                "PrimaryURL": "https://avd.example/CVE-2024-1",
            },
            "resource_regions": ["global"],
            "resource_services": ["lang-pkgs"],
            "first_seen_at": datetime(2026, 10, 1, tzinfo=UTC),
            "inserted_at": datetime(2026, 10, 1, tzinfo=UTC),
            "scan__provider__alias": "app-repo",
            "scan__provider__uid": "https://github.com/acme/app",
            "scan__provider__provider": "iac",
            "scan__scanner_args": {"source": "trivy_hub", "mode": "repo"},
        }
        item.update(overrides)
        return item

    def test_sca_row(self):
        row = sca_row(self._item(), {"uid": "package-lock.json:openssl"})
        assert row["cve"] == "CVE-2024-1"
        assert row["package"] == "openssl"
        assert row["installed_version"] == "3.0.1"
        assert row["fixed_version"] == "3.0.8"
        assert row["provider"] == "app-repo (repo)"
        assert row["target"] == "package-lock.json:openssl"

    def test_secret_row_never_includes_match(self):
        item = self._item(
            check_id="aws-access-key-id",
            raw_result={"RuleID": "aws-access-key-id", "Category": "AWS", "StartLine": 12},
        )
        row = secret_row(item, {"uid": "config/.env"})
        assert row["location"] == "config/.env:12"
        assert row["detail"] == "AWS"
        assert "AKIA" not in json.dumps(row)

    def test_secret_row_keeps_cloud_detail(self):
        item = self._item(raw_result={}, status_extended="Secret in Lambda env")
        assert secret_row(item, {})["detail"] == "Secret in Lambda env"

    def test_sast_row(self):
        item = self._item(
            check_id="python.lang.security.eval",
            raw_result={
                "path": "app/main.py",
                "start": {"line": 42},
                "extra": {"metadata": {"cwe": ["CWE-95"]}},
            },
            scan__scanner_args={"source": "trivy_hub", "mode": "sast"},
        )
        row = sast_row(item, {})
        assert row["location"] == "app/main.py:42"
        assert row["cwe"] == "CWE-95"
        assert row["provider"] == "app-repo (sast)"
