"""Assessment engine: polarity, dedupe, reconciliation, scoring, recommendations."""

from __future__ import annotations

import json
import time
from datetime import timedelta

import pytest
from cloudsneeker_api.reports.assessment import (
    accuracy,
    ai,
    quality,
    recommend,
    roadmap,
    scoring,
)
from cloudsneeker_api.reports.assessment.builder import (
    DEFAULT_SECTIONS,
    OPTIONAL_SECTIONS,
    SPECS,
    appendix,
    build_content,
    period_window,
)
from cloudsneeker_api.reports.assessment.model import (
    AREA_APPSEC,
    AREA_CLOUD,
    AREA_GOVERNANCE,
    CATEGORY_SECRET,
    CATEGORY_VULNERABILITY,
    NOT_ASSESSED,
)
from cloudsneeker_api.tests import assessment_fixtures as fx


def _build(dataset, report_type="security_assessment", sections=DEFAULT_SECTIONS):
    return build_content(
        spec=SPECS[report_type],
        dataset=dataset,
        now=fx.NOW,
        period_label="Last 30 days",
        period_from=fx.NOW - timedelta(days=30),
        period_to=fx.NOW,
        sections=list(sections),
        scope={"providers": ["production-aws"], "frameworks": [], "stale_days": 7},
    )


class TestPolarity:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("FAIL", "FAIL"),
            ("fail", "FAIL"),
            ("Passed", "PASS"),
            ("PASS", "PASS"),
            ("MANUAL", "MANUAL"),
            ("", "UNKNOWN"),
            (None, "UNKNOWN"),
            ("muted", "UNKNOWN"),
        ],
    )
    def test_normalize_status(self, raw, expected):
        assert accuracy.normalize_status(raw) == expected

    def test_pass_is_never_open(self):
        assert not fx.finding(status="PASS").is_open
        assert not fx.finding(status="MANUAL").is_open
        assert not fx.finding(status="FAIL", muted=True).is_open
        assert fx.finding(status="FAIL").is_open

    def test_triage_does_not_close_a_failing_finding(self):
        assert fx.finding(triage_status="resolved").is_open

    def test_conflicts_and_unknown_are_reported(self):
        report = accuracy.validate_polarity(
            [
                fx.finding(),
                fx.finding(status="PASS"),
                fx.finding(status="UNKNOWN", check_id="x"),
            ],
            db_conflicts=2,
        )
        assert report.conflicts == 3
        assert report.unknown_status == 1
        assert len(report.issues) == 2

    def test_pass_records_never_reach_exposure_lists(self):
        content, findings = _build(fx.duplicates_dataset())
        refs = {risk["lead_ref"] for risk in content["top_risks"]}
        by_ref = {item.ref: item for item in findings}
        assert refs and all(by_ref[ref].status == "FAIL" for ref in refs)


class TestDedupe:
    def test_merges_same_identity_and_keeps_latest(self):
        result = accuracy.dedupe(fx.duplicates_dataset().findings)
        assert result.input_count == 4
        assert result.removed == 1
        merged = next(item for item in result.findings if item.source_id == "dup-b")
        assert merged.duplicate_source_ids == ["dup-a"]
        # The earliest first-seen of the group is kept.
        assert merged.first_seen_at == fx.NOW - timedelta(days=30)

    @pytest.mark.parametrize(
        "field, value",
        [
            ("account", "999"),
            ("resource_uid", "other"),
            ("check_id", "other"),
            ("scanner", "repo"),
            ("status", "PASS"),
            ("provider_type", "azure"),
        ],
    )
    def test_any_key_part_keeps_records_apart(self, field, value):
        result = accuracy.dedupe(
            [fx.finding(source_id="a"), fx.finding(source_id="b", **{field: value})]
        )
        assert result.removed == 0


class TestTotals:
    def test_reconcile_and_resources_counted_apart(self):
        findings = [
            fx.finding(source_id="1", resource_uid="r1"),
            fx.finding(
                source_id="2", resource_uid="r1", check_id="other", severity="critical"
            ),
            fx.finding(source_id="3", resource_uid="r2", muted=True),
            fx.finding(source_id="4", status="MANUAL"),
            fx.finding(source_id="5", status="UNKNOWN"),
        ]
        totals = accuracy.compute_totals(findings, {AREA_CLOUD: {"high": 7}})
        assert (totals.open, totals.muted, totals.manual, totals.unknown) == (
            2,
            1,
            1,
            1,
        )
        assert totals.affected_resources == 1
        assert totals.passed == 7
        assert all(check.ok for check in accuracy.reconcile(totals))

    def test_broken_totals_are_detected(self):
        totals = accuracy.Totals(
            records=3,
            open=3,
            open_by_severity={"high": 2},
            open_by_area={"cloud": 3},
            open_by_category={"x": 3},
        )
        failed = {check.rule for check in accuracy.reconcile(totals) if not check.ok}
        assert failed == {"severity_buckets"}

    def test_coverage_states_and_warnings(self):
        assert accuracy.coverage_state(None, fx.NOW) == "not_assessed"
        assert accuracy.coverage_state(fx.NOW - timedelta(days=8), fx.NOW) == "stale"
        assert accuracy.coverage_state(fx.NOW - timedelta(days=2), fx.NOW) == "current"
        warnings = accuracy.coverage_warnings(fx.stale_partial_dataset().coverage)
        assert len(warnings) == 2
        assert "not assessed" in warnings[1]


class TestScoring:
    def test_unassessed_area_scores_none_and_overall_renormalizes(self):
        findings = [fx.finding(severity="critical")]
        scores = scoring.area_scores(findings, {AREA_CLOUD: {"high": 10}}, {AREA_CLOUD})
        assert scores[AREA_APPSEC] is None and scores[AREA_GOVERNANCE] is None
        assert scoring.overall_score(scores) == scores[AREA_CLOUD]

    def test_assessed_clean_area_scores_full(self):
        scores = scoring.area_scores([], {}, {AREA_APPSEC})
        assert scores[AREA_APPSEC] == 100.0

    def test_no_assessment_has_no_score(self):
        assert scoring.overall_score({AREA_CLOUD: None}) is None

    def test_kpis_missing_values_are_none_not_zero(self):
        metrics = scoring.kpis(
            [],
            accuracy.Totals(),
            now=fx.NOW,
            sources_assessed=0,
            sources_in_scope=0,
            frameworks_assessed=0,
        )
        assert metrics["fix_available_pct"] is None
        assert metrics["median_age_critical_high_days"] is None
        assert metrics["coverage_pct"] is None


class TestRecommendations:
    @pytest.mark.parametrize(
        "severity, category, fix, expected",
        [
            ("critical", "cloud_configuration", True, "P0"),
            ("critical", CATEGORY_VULNERABILITY, False, "P1"),
            ("critical", CATEGORY_SECRET, False, "P0"),
            ("high", CATEGORY_VULNERABILITY, True, "P1"),
            ("high", CATEGORY_VULNERABILITY, False, "P2"),
            ("medium", CATEGORY_VULNERABILITY, True, "P2"),
            ("low", CATEGORY_VULNERABILITY, True, "P3"),
            ("informational", CATEGORY_VULNERABILITY, True, None),
        ],
    )
    def test_priority_rules(self, severity, category, fix, expected):
        item = fx.finding(
            severity=severity, category=category, fix={"fix_available": fix}
        )
        assert recommend.priority_for(item) == expected

    def test_complete_recommendation_without_invented_scores(self):
        item = fx.finding(ref="F-0001", advisory={})
        rec = recommend.recommend(item, now=fx.NOW)
        for key in (
            "issue",
            "why_it_matters",
            "justification",
            "instructions",
            "validation",
            "prevention",
            "suggested_owner",
            "sla_days",
            "target_date",
            "expected_outcome",
        ):
            assert rec[key], key
        assert rec["target_date"] == (fx.NOW + timedelta(days=7)).date().isoformat()
        assert "CVSS" not in rec["justification"]
        assert rec["business_impact"]["confirmed"].startswith("Scanner evidence")
        assert rec["business_impact"]["potential"]

    def test_advisory_cvss_is_attributed_when_recorded(self):
        item = fx.finding(advisory={"cvss_published": "9.8 (nvd)"})
        assert (
            "advisory-published CVSS 9.8 (nvd)"
            in recommend.recommend(item, now=fx.NOW)["justification"]
        )

    def test_placeholders_are_marked(self):
        rec = recommend.recommend(fx.finding(), now=fx.NOW)
        assert "<BUCKET_NAME>" in rec["commands"][0]["code"]
        assert rec["placeholder_note"]

    def test_cloud_guidance_drops_links_and_upstream_name(self):
        upstream = "".join(("Pro", "wler"))
        item = fx.finding(
            remediation_code={
                "cli": "https://docs.example.com/x",
                "terraform": f"```hcl\nresource {{}} # {upstream}\n```",
            },
            references=[
                f"https://hub.{upstream.lower()}.com/check/x",
                "https://docs.aws.amazon.com/x",
            ],
        )
        rec = recommend.recommend(item, now=fx.NOW)
        assert [command["kind"] for command in rec["commands"]] == ["Terraform"]
        assert upstream.lower() not in json.dumps(rec).lower()
        assert rec["references"] == ["https://docs.aws.amazon.com/x"]

    @pytest.mark.parametrize(
        "purl, expected",
        [
            ("pkg:npm/braces@3.0.2", "npm install braces@3.0.3"),
            ("pkg:pypi/braces@3.0.2", 'pip install "braces>=3.0.3"'),
            ("pkg:golang/braces@3.0.2", "go get braces@v3.0.3"),
        ],
    )
    def test_package_upgrade_commands_use_real_values(self, purl, expected):
        item = fx.finding(
            category=CATEGORY_VULNERABILITY,
            fix={
                "fix_available": True,
                "fixed_version": "3.0.3",
                "package": "braces",
                "purl": purl,
            },
        )
        rec = recommend.recommend(item, now=fx.NOW)
        assert rec["commands"][0]["code"].startswith(expected)
        assert not rec["placeholder_note"]

    def test_no_fixed_version_no_command(self):
        item = fx.finding(
            category=CATEGORY_VULNERABILITY,
            fix={"fix_available": False, "package": "x", "purl": "pkg:npm/x@1"},
        )
        assert recommend.recommend(item, now=fx.NOW)["commands"] == []

    def test_secret_impact_is_confirmed(self):
        item = fx.finding(category=CATEGORY_SECRET, location="config.env:3")
        rec = recommend.recommend(item, now=fx.NOW)
        assert "config.env:3" in rec["business_impact"]["confirmed"]
        assert rec["instructions"][0].startswith("Revoke")


class TestRoadmap:
    def test_groups_by_issue_and_bounds_windows(self):
        findings = fx.multi_cloud_dataset().findings
        unique = accuracy.dedupe(findings).findings
        roadmap.assign_refs(unique)
        groups = roadmap.issue_groups(unique, now=fx.NOW)
        assert len({group.key for group in groups}) == len(groups)
        windows = roadmap.roadmap(groups)
        assert [window["id"] for window in windows] == [
            "0-24h",
            "1-7d",
            "8-30d",
            "31-90d",
        ]
        for window in windows:
            assert len(window["items"]) <= roadmap.MAX_ITEMS_PER_WINDOW
            for item in window["items"]:
                assert item["priority"] == window["priority"]
        assert all(
            group.priority for group in groups if group.lead.severity != "informational"
        )

    def test_refs_are_stable(self):
        first = accuracy.dedupe(fx.multi_cloud_dataset().findings).findings
        second = accuracy.dedupe(
            list(reversed(fx.multi_cloud_dataset().findings))
        ).findings
        roadmap.assign_refs(first)
        roadmap.assign_refs(second)
        assert {f.source_id: f.ref for f in first} == {
            f.source_id: f.ref for f in second
        }


class TestBuildContent:
    def test_empty_dataset_is_not_assessed_not_zero(self):
        content, findings = _build(fx.empty_dataset())
        assert findings == []
        assert content["summary"]["score"] is None
        assert content["summary"]["grade"] == "N/A"
        assert all(
            row["open_findings"] == NOT_ASSESSED for row in content["summary"]["areas"]
        )
        assert "No source" in content["summary"]["narrative"][0]["text"]
        result = quality.evaluate(content, findings, None)
        assert result["distributable"], result

    def test_multi_cloud_executive(self):
        content, findings = _build(fx.multi_cloud_dataset())
        summary = content["summary"]
        assert summary["score"] is not None
        assert {row["area"] for row in summary["areas"]} == {
            AREA_CLOUD,
            AREA_APPSEC,
            AREA_GOVERNANCE,
        }
        assert all(rule["ok"] for rule in content["accuracy"]["reconciliation"])
        assert summary["kpis"]["affected_resources"] <= summary["kpis"]["open_findings"]
        assert content["distribution"]["by_provider"]
        assert 1 <= len(content["top_risks"]) <= 10
        result = quality.evaluate(content, findings, None)
        assert not [c for c in result["checks"] if c["status"] == "fail"], result

    def test_duplicates_counted_once(self):
        content, _ = _build(fx.duplicates_dataset())
        assert content["accuracy"]["duplicates_merged"] == 1
        assert content["summary"]["kpis"]["open_findings"] == 2

    @pytest.mark.parametrize(
        "report_type, area",
        [
            ("appsec_assessment", AREA_APPSEC),
            ("cloud_assessment", AREA_CLOUD),
            ("governance_assessment", AREA_GOVERNANCE),
        ],
    )
    def test_each_type_keeps_only_its_area(self, report_type, area):
        content, findings = _build(fx.multi_cloud_dataset(), report_type)
        assert {item.area for item in findings} == {area}
        assert [row["area"] for row in content["summary"]["areas"]] == [area]
        assert {row["area"] for row in content["coverage"]["rows"]} <= {
            {
                "cloud": "Cloud security",
                "application_security": "Application security",
                "governance": "Governance",
            }[area]
        }

    def test_compliance_states_are_separated(self):
        content, _ = _build(fx.multi_cloud_dataset(), "governance_assessment")
        compliance = content["compliance"]
        assert [row["framework"] for row in compliance["assessed"]][
            0
        ] == "iso27001_2022_aws"
        assert compliance["enabled_not_assessed"] == ["pci_4.0_aws"]
        assert compliance["available_count"] == 14
        assert "not an audit, certification" in compliance["disclaimer"]
        assert (
            _build(fx.multi_cloud_dataset(), "appsec_assessment")[0]["compliance"]
            is None
        )

    def test_trend_excludes_scope_changes(self):
        content, _ = _build(fx.stale_partial_dataset())
        trend = content["trend"]
        assert any(not point["comparable"] for point in trend["points"])
        first_comparable = next(
            point for point in trend["points"] if point["comparable"]
        )
        assert trend["change"]["from_date"] == first_comparable["date"]
        assert len(trend["notes"]) == 2

    def test_stale_partial_warns_but_stays_distributable(self):
        content, findings = _build(fx.stale_partial_dataset())
        assert len(content["coverage"]["warnings"]) >= 2
        governance = next(
            row for row in content["summary"]["areas"] if row["area"] == AREA_GOVERNANCE
        )
        assert governance["assessed"] is False
        result = quality.evaluate(content, findings, None)
        assert result["distributable"]
        assert result["status"] == "warn"

    def test_missing_evidence_still_gets_full_recommendations(self):
        content, findings = _build(fx.missing_evidence_dataset())
        risk = content["top_risks"][0]["recommendation"]
        assert risk["instructions"] and risk["validation"] and risk["suggested_owner"]
        assert risk["business_impact"]["confirmed"] == ""
        assert content["accuracy"]["polarity"]["unknown_status"] == 1
        assert quality.evaluate(content, findings, None)["distributable"]

    def test_thousands_of_findings(self):
        started = time.monotonic()
        content, findings = _build(fx.large_dataset(6000))
        assert time.monotonic() - started < 30
        assert all(rule["ok"] for rule in content["accuracy"]["reconciliation"])
        assert content["appendix"]["printed"] <= 1500
        assert (
            content["appendix"]["total"] == content["summary"]["kpis"]["open_findings"]
        )

    def test_sections_can_be_left_out(self):
        content, _ = _build(fx.multi_cloud_dataset(), sections=[])
        for key in (
            "trend",
            "top_risks",
            "posture",
            "compliance",
            "roadmap",
            "appendix",
        ):
            assert content[key] is None
        assert set(DEFAULT_SECTIONS) < set(OPTIONAL_SECTIONS)


class TestAppendix:
    def test_budget_goes_to_the_most_severe_first(self):
        findings = [
            fx.finding(
                source_id=f"l{i}",
                severity="low",
                category="license",
                resource_uid=f"l{i}",
            )
            for i in range(30)
        ]
        findings += [
            fx.finding(source_id=f"c{i}", severity="critical", resource_uid=f"c{i}")
            for i in range(30)
        ]
        roadmap.assign_refs(findings)
        result = appendix(findings, limit=40)
        printed = {
            sev["severity"]: len(sev["rows"])
            for g in result["groups"]
            for sev in g["severities"]
        }
        assert printed == {"critical": 30, "low": 10}
        assert result["truncated"]


class TestPeriods:
    def test_windows(self):
        assert period_window("7d", fx.NOW, None, None)[2] == "Last 7 days"
        assert period_window("latest", fx.NOW, None, None) == (
            None,
            None,
            "Latest results",
        )
        start, end, label = period_window(
            "custom", fx.NOW, fx.NOW - timedelta(days=3), None
        )
        assert (
            start == fx.NOW - timedelta(days=3)
            and end is None
            and label.endswith("to now")
        )


class TestQuality:
    def test_open_exposure_only(self):
        content, findings = _build(fx.multi_cloud_dataset())
        lead = content["top_risks"][0]["lead_ref"]
        next(item for item in findings if item.ref == lead).status = "PASS"
        result = quality.evaluate(content, findings, None)
        assert not result["distributable"]
        assert any(
            c["id"] == "polarity_exposure_only_open" and c["status"] == "fail"
            for c in result["checks"]
        )

    def test_layout_failures_block_distribution(self):
        content, findings = _build(fx.multi_cloud_dataset())
        layout = {
            "pages": 9,
            "blank_pages": [4],
            "orphan_headings": [],
            "toc_entries": 5,
            "bookmarks": 5,
            "metadata": True,
        }
        result = quality.evaluate(content, findings, layout)
        assert not result["distributable"]

    def test_zero_instead_of_not_assessed_fails(self):
        content, findings = _build(fx.empty_dataset())
        content["summary"]["areas"][0]["open_findings"] = 0
        assert not quality.evaluate(content, findings, None)["distributable"]

    def test_upstream_branding_fails(self):
        content, findings = _build(fx.multi_cloud_dataset())
        content["methodology"].append("".join(("Pro", "wler")) + " output")
        assert not quality.evaluate(content, findings, None)["distributable"]

    def test_invented_score_field_fails(self):
        content, findings = _build(fx.multi_cloud_dataset())
        content["top_risks"][0]["recommendation"]["advisory"]["epss"] = 0.9
        assert not quality.evaluate(content, findings, None)["distributable"]


class TestAiInsights:
    def _facts(self):
        content, _ = _build(fx.multi_cloud_dataset())
        return content, ai.fact_sheet(content)

    def test_uncited_and_unknown_citations_are_dropped(self):
        content, facts = self._facts()
        lead = content["top_risks"][0]["lead_ref"]
        reply = json.dumps(
            {
                "insights": [
                    {
                        "statement": "Most risk sits in one issue.",
                        "kind": "interpretation",
                        "citations": [lead],
                    },
                    {"statement": "No source.", "kind": "fact", "citations": []},
                    {
                        "statement": "Made up.",
                        "kind": "fact",
                        "citations": ["F-9999", "epss"],
                    },
                    {
                        "statement": "Bad kind.",
                        "kind": "guess",
                        "citations": ["open_findings"],
                    },
                    {
                        "statement": "Open count.",
                        "kind": "fact",
                        "citations": ["open_findings"],
                    },
                ]
            }
        )
        insights = ai.parse_insights(f"Here you go:\n{reply}", facts)
        assert [item["statement"] for item in insights] == [
            "Most risk sits in one issue.",
            "Open count.",
        ]

    def test_garbage_reply(self):
        _, facts = self._facts()
        assert ai.parse_insights("no json here", facts) == []

    def test_insufficient_data_without_assessment(self):
        content, _ = _build(fx.empty_dataset())
        result = ai.ai_insights("00000000-0000-0000-0000-000000000000", content)
        assert result["status"] == "insufficient_data"
        assert result["insights"] == []

    def test_unconfigured_llm_is_explicit(self, monkeypatch):
        content, _ = self._facts()
        from cloudsneeker_api.services import custodian_ai

        def raise_unconfigured(_tenant):
            raise custodian_ai.PolicyGenerationError(
                "Seeker AI is not set up.", code="not_configured"
            )

        monkeypatch.setattr(custodian_ai, "resolve_llm_settings", raise_unconfigured)
        result = ai.ai_insights("00000000-0000-0000-0000-000000000000", content)
        assert result["status"] == "unavailable"
        assert "not set up" in result["message"]

    def test_valid_reply_is_kept_with_model(self, monkeypatch):
        content, facts = self._facts()
        from cloudsneeker_api.services import custodian_ai

        settings = custodian_ai.LLMSettings(
            provider_type="openai", model_id="model-x", config=None
        )
        monkeypatch.setattr(
            custodian_ai, "resolve_llm_settings", lambda _tenant: settings
        )
        monkeypatch.setattr(
            custodian_ai,
            "complete_chat",
            lambda _settings, _messages: json.dumps(
                {
                    "insights": [
                        {
                            "statement": "Critical count.",
                            "kind": "fact",
                            "citations": ["critical"],
                        }
                    ]
                }
            ),
        )
        result = ai.ai_insights("00000000-0000-0000-0000-000000000000", content)
        assert result["status"] == "ok" and result["model"] == "model-x"
        assert result["insights"][0]["citations"] == ["critical"]


class TestFrameworkLabels:
    def test_upstream_framework_ids_are_rebranded(self):
        from cloudsneeker_api.reports.assessment.builder import framework_label
        from cloudsneeker_api.reports.assessment.model import ComplianceFramework

        upstream = "".join(("pro", "wler")) + "_threatscore_aws"
        assert "wler" not in framework_label(upstream)
        assert framework_label("cis_2.0_aws") == "cis_2.0_aws"
        dataset = fx.multi_cloud_dataset()
        dataset.compliance.append(ComplianceFramework(upstream, ["aws"], "assessed", passed=3, failed=1, total=4))
        dataset.compliance.append(ComplianceFramework(upstream + "_x", ["aws"], "available"))
        content, findings = _build(dataset, "governance_assessment")
        assert quality.evaluate(content, findings, None)["distributable"]
