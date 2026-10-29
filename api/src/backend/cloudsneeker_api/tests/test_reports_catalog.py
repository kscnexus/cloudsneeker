"""Report catalog, parameter validation, and pure scoring helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from cloudsneeker_api.reports import catalog
from cloudsneeker_api.reports.catalog import (
    REPORT_FORMATS,
    REPORT_TYPES,
    ReportParamsError,
    filters_from_params,
    get_report_type,
    report_filename,
    validate_formats,
    validate_params,
)
from cloudsneeker_api.reports.data.common import (
    FindingStats,
    business_impact,
    grade_for,
    remediation_text,
    requirement_status,
    security_score,
    stream_mode,
)
from cloudsneeker_api.reports.data.executive import (
    executive_headline,
    next_actions,
    overall_score,
)
from cloudsneeker_api.reports.data.findings_report import headline_for
from cloudsneeker_api.reports.data.governance import governance_score
from cloudsneeker_api.reports.schema import (
    ReportData,
    ReportFilters,
    ReportTable,
    empty_severity_counts,
)


class TestCatalog:
    def test_lists_every_report_type(self):
        assert set(REPORT_TYPES) == {
            "executive",
            "cloud_posture",
            "compliance",
            "sca",
            "sast",
            "container",
            "iac",
            "secrets",
            "governance",
        }

    def test_compliance_requires_framework(self):
        spec = get_report_type("compliance")
        assert spec.required_params == ("compliance_id",)
        assert "scan_id" in spec.to_dict()["parameters"]["optional"]

    def test_type_document_lists_formats(self):
        document = get_report_type("executive").to_dict()
        assert document["formats"] == list(REPORT_FORMATS)
        assert document["audience"] == "management"
        assert "provider_ids" in document["parameters"]["optional"]

    def test_unknown_type_raises(self):
        with pytest.raises(ReportParamsError, match="report_type must be one of"):
            get_report_type("nope")


class TestValidateFormats:
    def test_defaults_to_pdf_and_always_adds_json(self):
        assert validate_formats(None) == ["pdf", "json"]

    def test_deduplicates_and_lowercases(self):
        assert validate_formats(["XLSX", "csv", "xlsx"]) == ["xlsx", "csv", "json"]

    def test_accepts_comma_string(self):
        assert validate_formats("pdf,csv") == ["pdf", "csv", "json"]

    def test_keeps_json_once(self):
        assert validate_formats(["json"]) == ["json"]

    def test_rejects_unknown_format(self):
        with pytest.raises(ReportParamsError, match="Unknown format"):
            validate_formats(["docx"])

    def test_rejects_non_list(self):
        with pytest.raises(ReportParamsError, match="must be a list"):
            validate_formats({"pdf": True})


class TestValidateParams:
    def test_normalizes_defaults(self):
        assert validate_params("executive", None) == {
            "provider_ids": [],
            "date_from": None,
            "date_to": None,
            "severity_floor": None,
            "trend_points": 10,
        }

    def test_normalizes_providers_dates_and_severity(self):
        provider = str(uuid4())
        params = validate_params(
            "cloud_posture",
            {
                "provider_ids": [provider, provider],
                "date_from": "2026-01-01",
                "date_to": "2026-01-31",
                "severity_floor": "HIGH",
                "trend_points": "5",
            },
        )
        assert params["provider_ids"] == [provider]
        assert params["date_from"].startswith("2026-01-01T00:00:00")
        assert params["date_to"].startswith("2026-01-31T23:59:59")
        assert params["severity_floor"] == "high"
        assert params["trend_points"] == 5

    def test_accepts_comma_separated_providers(self):
        first, second = str(uuid4()), str(uuid4())
        params = validate_params("sca", {"provider_ids": f"{first},{second}"})
        assert params["provider_ids"] == sorted([first, second])

    def test_compliance_keeps_framework_and_scan(self):
        scan_id = str(uuid4())
        params = validate_params(
            "compliance", {"compliance_id": "cis_2.0_aws", "scan_id": scan_id}
        )
        assert params["compliance_id"] == "cis_2.0_aws"
        assert params["scan_id"] == scan_id

    @pytest.mark.parametrize(
        "params,message",
        [
            ({"bogus": 1}, "Unknown parameter"),
            ({"provider_ids": ["not-a-uuid"]}, "provider_ids must be a UUID"),
            ({"provider_ids": {"a": 1}}, "provider_ids must be a list"),
            ({"date_from": "yesterday"}, "Invalid date"),
            (
                {"date_from": "2026-02-01", "date_to": "2026-01-01"},
                "date_from must be before",
            ),
            ({"severity_floor": "urgent"}, "severity_floor must be one of"),
            ({"trend_points": "x"}, "trend_points must be an integer"),
            ({"trend_points": 99}, "trend_points must be between"),
        ],
    )
    def test_rejects_invalid(self, params, message):
        with pytest.raises(ReportParamsError, match=message):
            validate_params("cloud_posture", params)

    def test_compliance_without_framework_fails(self):
        with pytest.raises(ReportParamsError, match="compliance_id is required"):
            validate_params("compliance", {})

    def test_scan_id_only_for_compliance(self):
        with pytest.raises(ReportParamsError, match="Unknown parameter"):
            validate_params("executive", {"scan_id": str(uuid4())})

    def test_rejects_non_mapping(self):
        with pytest.raises(ReportParamsError, match="params must be an object"):
            validate_params("executive", ["a"])

    def test_round_trips_into_filters(self):
        params = validate_params(
            "compliance",
            {"compliance_id": "cis", "date_from": "2026-01-01", "severity_floor": "medium"},
        )
        filters = filters_from_params(params)
        assert filters.compliance_id == "cis"
        assert filters.date_from == datetime(2026, 1, 1, tzinfo=UTC)
        assert filters.severities() == ["critical", "high", "medium"]
        # Normalized params are idempotent.
        assert validate_params("compliance", params) == params


class TestFilenameAndSchema:
    def test_filename_uses_brand_slug_and_date(self):
        name = report_filename("cloud_posture", "pdf", datetime(2026, 10, 29, tzinfo=UTC))
        assert name == "cloudsneeker-cloud-posture-2026-10-29.pdf"

    def test_severities_without_floor(self):
        assert ReportFilters().severities() == list(catalog.SEVERITY_ORDER)

    def test_report_data_to_dict_bounds_tables(self):
        table = ReportTable(
            key="findings",
            title="Findings",
            columns=[("a", "A")],
            rows=[{"a": index} for index in range(5)],
            total=5,
        )
        data = ReportData(
            report_type="sca",
            title="t",
            generated_at=datetime(2026, 1, 1, tzinfo=UTC),
            filters=ReportFilters(date_from=datetime(2026, 1, 1, tzinfo=UTC)),
            tables=[table],
            extra={"when": datetime(2026, 1, 2, tzinfo=UTC), "obj": object},
        )
        payload = data.to_dict(table_row_limit=2)
        assert payload["generated_at"] == "2026-01-01T00:00:00+00:00"
        assert payload["filters"]["date_from"] == "2026-01-01T00:00:00+00:00"
        assert len(payload["tables"][0]["rows"]) == 2
        assert payload["tables"][0]["truncated"] is True
        assert payload["tables"][0]["columns"] == [{"field": "a", "header": "A"}]
        assert payload["extra"]["when"] == "2026-01-02T00:00:00+00:00"
        assert isinstance(payload["extra"]["obj"], str)
        assert data.is_empty is False


class TestScoring:
    def test_no_findings_has_no_score(self):
        assert security_score(empty_severity_counts(), empty_severity_counts()) is None
        assert grade_for(None) == "N/A"

    def test_weighted_pass_ratio(self):
        fail = {**empty_severity_counts(), "critical": 1}
        passed = {**empty_severity_counts(), "critical": 9}
        assert security_score(fail, passed) == 90.0

    def test_exposure_only_decays(self):
        fail = {**empty_severity_counts(), "critical": 5}
        assert security_score(fail, empty_severity_counts()) == 50.0

    def test_informational_only_is_perfect(self):
        fail = {**empty_severity_counts(), "informational": 3}
        assert security_score(fail, empty_severity_counts()) == 100.0

    @pytest.mark.parametrize(
        "score,grade",
        [(95, "A"), (90, "A"), (85, "B"), (75, "C"), (65, "D"), (10, "F")],
    )
    def test_grades(self, score, grade):
        assert grade_for(score) == grade

    @pytest.mark.parametrize(
        "statuses,expected",
        [
            (["PASS", "FAIL"], "FAIL"),
            (["PASS", "PASS"], "PASS"),
            (["PASS", "MANUAL"], "MANUAL"),
            ([], "MANUAL"),
        ],
    )
    def test_requirement_status(self, statuses, expected):
        assert requirement_status(statuses) == expected

    def test_stream_mode(self):
        assert stream_mode({"source": "trivy_hub", "mode": "sbom"}, "iac") == "sbom"
        assert stream_mode({}, "iac") == "iac"
        assert stream_mode(None, "aws") == "aws"

    def test_remediation_prefers_prowler_text(self):
        metadata = {"Remediation": {"Recommendation": {"Text": "Enable MFA."}}}
        assert remediation_text(metadata) == "Enable MFA."

    def test_remediation_uses_fixed_version(self):
        raw = {"PkgName": "openssl", "FixedVersion": "3.0.8"}
        assert remediation_text({}, raw) == "Upgrade openssl to 3.0.8 or later."

    def test_remediation_uses_resolution_then_default(self):
        assert remediation_text({}, {"Resolution": "Set x."}) == "Set x."
        assert "vendor-recommended" in remediation_text({}, {})

    def test_business_impact(self):
        assert business_impact("high", {"Risk": "Data exposure."}) == "Data exposure."
        assert "breach" in business_impact("critical", {})
        assert business_impact("unknown", {}).startswith("Weakens")

    def test_governance_score(self):
        assert governance_score(0, 0) is None
        assert governance_score(4, 1) == 75.0

    def test_overall_score_skips_missing_domains(self):
        assert overall_score({"cloud": None, "application": None}) is None
        assert overall_score({"cloud": 80.0, "application": None}) == 80.0
        assert overall_score({"cloud": 100.0, "governance": 0.0}) == 80.0


class TestHeadlines:
    def test_findings_headlines(self):
        assert headline_for("cloud findings", 0, 0, 0, "A").startswith("No open")
        assert "2 of them critical or high" in headline_for("x", 5, 1, 1, "C")
        assert "none critical or high" in headline_for("x", 5, 0, 0, "B")

    def test_executive_headline_without_data(self):
        assert "No completed scans" in executive_headline("N/A", None, 0, 0, 0, 0, None)

    def test_executive_headline_with_data(self):
        text = executive_headline("B", 82.4, 10, 2, 3, 4, 71.0)
        assert text.startswith("Overall security grade B (82/100).")
        assert "2 critical and 3 high" in text
        assert "Compliance averages 71%" in text
        assert "top five risks" in text

    def test_executive_headline_clean(self):
        text = executive_headline("A", 99.0, 0, 0, 0, 2, None)
        assert "No open issues across 2 source(s)." in text
        assert "top five" not in text


class TestNextActions:
    def _stats(self, critical=0, high=0) -> FindingStats:
        stats = FindingStats()
        stats.fail_by_severity["critical"] = critical
        stats.fail_by_severity["high"] = high
        return stats

    def test_prioritizes_critical_secrets_compliance(self):
        actions = next_actions(
            cloud=self._stats(critical=2, high=1),
            application=self._stats(),
            secrets_open=3,
            posture=[{"compliance_id": "cis", "pass_pct": 40.0}],
            governance_kpis={"policies_with_matches": 1, "matched_resources": 7},
            risks=[{"check_id": "c1", "title": "Root MFA"}],
            has_cloud=True,
            has_application=False,
        )
        texts = [item["action"] for item in actions]
        assert texts[0].startswith("Fix the 2 critical issue(s), starting with 'Root MFA'")
        assert any("exposed secret" in text for text in texts)
        assert any("cis" in text for text in texts)
        assert any("high-severity" in text for text in texts)
        assert len(actions) == 6
        assert [item["priority"] for item in actions] == list(range(1, 7))

    def test_coverage_gaps_and_clean_state(self):
        actions = next_actions(
            cloud=self._stats(),
            application=self._stats(),
            secrets_open=0,
            posture=[],
            governance_kpis={},
            risks=[],
            has_cloud=False,
            has_application=True,
        )
        assert actions[0]["action"].startswith("Connect your cloud accounts")
        clean = next_actions(
            cloud=self._stats(),
            application=self._stats(),
            secrets_open=0,
            posture=[{"compliance_id": "cis", "pass_pct": 95.0}],
            governance_kpis={},
            risks=[],
            has_cloud=True,
            has_application=True,
        )
        assert clean == [
            {
                "priority": 1,
                "action": "Keep scans scheduled and review this report monthly.",
                "why": "No urgent issues are open; continuous coverage keeps it that way.",
            }
        ]
