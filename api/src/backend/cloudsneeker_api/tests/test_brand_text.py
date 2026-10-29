import pytest
from cloudsneeker_api.services.brand_text import scrub_engine_text


class TestScrubEngineText:
    def test_strips_log_prefix_and_temp_path(self):
        raw = (
            "2026-10-27 18:29:58,918: custodian.commands:ERROR invalid policy file: "
            "/tmp/cs-custodian-4_46uj8g/policy.yml error: Failed to validate policy"
        )
        assert scrub_engine_text(raw) == (
            "Invalid policy file: policy.yml error: Failed to validate policy"
        )

    @pytest.mark.parametrize(
        "raw, expected",
        [
            (
                "Cloud Custodian supports AWS and GCP only.",
                "Cloud Governance supports AWS and GCP only.",
            ),
            ("Unknown Trivy mode: x", "Unknown scanner mode: x"),
            ("trivy exited with code 1", "scanner exited with code 1"),
            ("opengrep scan timed out", "code analyzer scan timed out"),
            ("Semgrep rules failed to load", "code analyzer rules failed to load"),
            ("Trivy Hub target is invalid", "Application Security target is invalid"),
            ("c7n-org is not installed", "governance is not installed"),
        ],
    )
    def test_rewrites_engine_names(self, raw, expected):
        assert scrub_engine_text(raw) == expected

    def test_leaves_plain_messages_alone(self):
        assert scrub_engine_text("boom") == "boom"
        assert scrub_engine_text("Policy at index 0 requires a name.") == (
            "Policy at index 0 requires a name."
        )

    @pytest.mark.parametrize("raw", [None, ""])
    def test_empty_input(self, raw):
        assert scrub_engine_text(raw) == ""

    def test_replaces_other_temp_paths(self):
        assert scrub_engine_text("cannot read /tmp/work-1/out") == (
            "cannot read a temporary file"
        )
