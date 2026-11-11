"""How-to-fix fields on area findings (Application Security and Cloud)."""

from __future__ import annotations

import pytest
from api.models import Finding
from cloudsneeker_api.services.area_findings import AreaFindingsError, parse_query
from cloudsneeker_api.services.finding_fix import (
    best_fixed_version,
    empty_fix,
    finding_fix,
)
from cloudsneeker_api.tests.test_area_findings import (
    _app_security_scan,
    _finding,
    _list,
    _scan,
    _uids,
)

VULN_FIXED = {
    "VulnerabilityID": "CVE-2026-1",
    "PkgName": "PyJWT",
    "InstalledVersion": "2.8.0",
    "FixedVersion": "2.10.1",
    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2026-1",
    "References": ["https://github.com/advisories/GHSA-1", "not a url"],
}
VULN_UNFIXED = {
    "VulnerabilityID": "CVE-2026-2",
    "PkgName": "pillow",
    "InstalledVersion": "11.1.0",
    "FixedVersion": "",
}
MISCONFIG = {
    "ID": "AVD-DS-0002",
    "Title": "Image runs as root",
    "Resolution": "Add a USER instruction to the Dockerfile.",
    "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002",
}
SECRET = {
    "RuleID": "aws-access-key-id",
    "Category": "AWS",
    "Match": "AKIA****",
    "StartLine": 12,
}
LICENSE = {"Name": "GPL-3.0", "Category": "restricted", "PkgName": "foo"}
SEMGREP = {
    "check_id": "python.sql-injection",
    "path": "app/db.py",
    "start": {"line": 4},
    "extra": {
        "message": "Use parameterized queries.",
        "metadata": {"references": ["https://owasp.org/sqli"]},
    },
}


class TestFindingFix:
    def test_package_with_fixed_version(self):
        fix = finding_fix({}, VULN_FIXED)

        assert fix["fix_available"] is True
        assert fix["installed_version"] == "2.8.0"
        assert fix["fixed_version"] == "2.10.1"
        assert fix["fix_summary"] == "Upgrade PyJWT from 2.8.0 to 2.10.1 or later."
        assert fix["fix_references"] == [
            "https://avd.aquasec.com/nvd/cve-2026-1",
            "https://github.com/advisories/GHSA-1",
        ]

    def test_package_with_one_fix_per_release_line(self):
        fix = finding_fix(
            {},
            {
                **VULN_FIXED,
                "PkgName": "django",
                "InstalledVersion": "4.2.10",
                "FixedVersion": "5.2.8, 5.1.14, 4.2.26",
            },
        )

        assert fix["fixed_version"] == "4.2.26"
        assert fix["fix_summary"] == (
            "Upgrade django from 4.2.10 to 4.2.26 or later. "
            "Also fixed in 5.2.8, 5.1.14."
        )

    @pytest.mark.parametrize(
        ("installed", "fixed", "best"),
        [
            ("4.2.10", "5.0.8, 4.2.15", "4.2.15"),
            ("3.1.0", "5.0.8, 4.2.15", "4.2.15"),
            ("4.1.0", "5.0.8, 4.2.15", "4.2.15"),
            ("", "2.0, 1.5", "1.5"),
            ("1.0", "2.14.0", "2.14.0"),
        ],
    )
    def test_best_fixed_version(self, installed, fixed, best):
        assert best_fixed_version(installed, fixed)[0] == best

    def test_package_without_fixed_version(self):
        fix = finding_fix({}, VULN_UNFIXED)

        assert fix["fix_available"] is False
        assert "No fixed version of pillow" in fix["fix_summary"]
        assert fix["installed_version"] == "11.1.0"

    def test_misconfiguration_uses_resolution(self):
        fix = finding_fix({}, MISCONFIG)

        assert fix["fix_available"] is True
        assert fix["fix_summary"] == MISCONFIG["Resolution"]
        assert fix["fix_references"] == [MISCONFIG["PrimaryURL"]]

    def test_secret_says_rotate_and_remove(self):
        fix = finding_fix({}, SECRET)

        assert fix["fix_available"] is True
        assert "rotate" in fix["fix_summary"]
        assert "line 12" in fix["fix_summary"]

    def test_license(self):
        fix = finding_fix({}, LICENSE)

        assert fix["fix_available"] is True
        assert "GPL-3.0" in fix["fix_summary"]

    def test_semgrep_message_and_code_fix(self):
        assert finding_fix({}, SEMGREP)["fix_summary"] == "Use parameterized queries."
        with_code = {**SEMGREP, "extra": {**SEMGREP["extra"], "fix": "cur.execute(q, args)"}}
        assert "cur.execute(q, args)" in finding_fix({}, with_code)["fix_summary"]
        assert finding_fix({}, SEMGREP)["fix_references"] == ["https://owasp.org/sqli"]

    @pytest.mark.parametrize("key", ["Remediation", "remediation"])
    def test_cloud_check_recommendation_any_case(self, key):
        metadata = {
            key: {
                "Recommendation": {
                    "Text": "Block public access.",
                    "Url": "https://docs.example.com/s3",
                }
            }
        }

        fix = finding_fix(metadata, {})

        assert fix["fix_available"] is True
        assert fix["fix_summary"] == "Block public access."
        assert fix["fix_references"] == ["https://docs.example.com/s3"]

    def test_nothing_known(self):
        assert finding_fix({}, {}) == empty_fix()
        assert finding_fix(None, None) == empty_fix()


def test_fix_filter_is_validated():
    assert parse_query({"filter[area]": "cloud", "filter[fix]": "available"}).fix == (
        "available"
    )
    with pytest.raises(AreaFindingsError):
        parse_query({"filter[area]": "cloud", "filter[fix]": "maybe"})


@pytest.mark.django_db
class TestFixOnAreaFindings:
    def test_rows_carry_fix_fields(self, authenticated_client, aws_provider):
        scan = _app_security_scan(aws_provider)
        _finding(scan, "trivy-fixed", raw=VULN_FIXED)

        attributes = _list(authenticated_client, "application_security").json()[
            "data"
        ][0]["attributes"]

        assert attributes["fix_available"] is True
        assert attributes["fixed_version"] == "2.10.1"
        assert attributes["installed_version"] == "2.8.0"
        assert attributes["fix_summary"].startswith("Upgrade PyJWT")
        assert attributes["fix_references"][0].startswith("https://")

    def test_fix_filter(self, authenticated_client, aws_provider):
        scan = _app_security_scan(aws_provider)
        _finding(scan, "trivy-fixed", raw=VULN_FIXED)
        _finding(scan, "trivy-unfixed", raw=VULN_UNFIXED)
        _finding(scan, "trivy-misconfig", raw=MISCONFIG)
        _finding(scan, "trivy-secret", raw=SECRET)

        available = _uids(
            _list(authenticated_client, "application_security", **{"filter[fix]": "available"})
        )
        unavailable = _uids(
            _list(
                authenticated_client,
                "application_security",
                **{"filter[fix]": "unavailable"},
            )
        )

        assert sorted(available) == ["trivy-fixed", "trivy-misconfig", "trivy-secret"]
        assert unavailable == ["trivy-unfixed"]

    def test_governance_rows_have_empty_fix(self, authenticated_client, aws_provider):
        from cloudsneeker_api.tests.test_area_findings import _policy_run

        _policy_run(aws_provider, [{"VolumeId": "vol-1", "c7n:policy": "unused-ebs"}])

        attributes = _list(authenticated_client, "governance").json()["data"][0][
            "attributes"
        ]

        assert attributes["fix_available"] is False
        assert attributes["fix_references"] == []

    def test_cloud_filter_uses_check_recommendation(
        self, authenticated_client, aws_provider
    ):
        scan = _scan(aws_provider)
        fixable = _finding(scan, "cloud-fixable")
        Finding.all_objects.filter(pk=fixable.pk).update(
            check_metadata={
                "CheckTitle": "S3 public",
                "Remediation": {"Recommendation": {"Text": "Block public access."}},
            }
        )
        _finding(scan, "cloud-plain")

        assert _uids(
            _list(authenticated_client, "cloud", **{"filter[fix]": "available"})
        ) == ["cloud-fixable"]
