"""Exploit intelligence (EB-022): EPSS and CISA KEV feeds and their use."""

from __future__ import annotations

import gzip
import json
from datetime import date
from unittest.mock import patch

import pytest
from cloudsneeker_api.models import VulnerabilityIntel, VulnerabilityIntelFeed
from cloudsneeker_api.services import vuln_intel
from cloudsneeker_api.services.area_findings import parse_query
from cloudsneeker_api.services.vuln_intel import (
    EpssScore,
    FeedError,
    KevEntry,
    parse_epss,
    parse_kev,
)
from cloudsneeker_api.tasks import refresh_vuln_intel_task
from cloudsneeker_api.tests.test_area_findings import (
    _app_security_scan,
    _finding,
    _list,
    _policy_run,
    _scan,
    _uids,
)

EPSS_CSV = (
    "#model_version:v2025.03.14,score_date:2026-11-10T12:55:00Z\n"
    "cve,epss,percentile\n"
    "CVE-2021-44228,0.94358,0.99962\n"
    "CVE-2024-0001,0.00043,0.11000\n"
    "not-a-cve,0.5,0.5\n"
    "CVE-2024-0002,bad,0.1\n"
    "CVE-2024-0003,1.7,0.1\n"
)

KEV_JSON = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.11.07",
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "requiredAction": "Apply updates per vendor instructions.",
        },
        {
            "cveID": "CVE-2023-9999",
            "vulnerabilityName": "Other",
            "dateAdded": "2023-01-02",
            "dueDate": "bad-date",
            "knownRansomwareCampaignUse": "Unknown",
        },
        {"cveID": ""},
        "junk",
    ],
}


class TestParseEpss:
    def test_reads_gzip_and_skips_bad_rows(self):
        version, scores = parse_epss(gzip.compress(EPSS_CSV.encode()))
        assert version == "2026-11-10"
        assert scores == [
            EpssScore("CVE-2021-44228", 0.94358, 0.99962),
            EpssScore("CVE-2024-0001", 0.00043, 0.11),
        ]

    def test_reads_plain_csv_without_comment(self):
        version, scores = parse_epss(b"cve,epss,percentile\ncve-2020-1,0.1,0.2\n")
        assert version == ""
        assert scores == [EpssScore("CVE-2020-1", 0.1, 0.2)]

    @pytest.mark.parametrize(
        "payload",
        [b"\x1f\x8bnot gzip", b"a,b\n1,2\n", b"cve,epss,percentile\n"],
    )
    def test_rejects_other_files(self, payload):
        with pytest.raises(FeedError):
            parse_epss(payload)


class TestParseKev:
    def test_reads_entries(self):
        version, entries = parse_kev(json.dumps(KEV_JSON).encode())
        assert version == "2026.11.07"
        by_cve = {entry.cve_id: entry for entry in entries}
        assert set(by_cve) == {"CVE-2021-44228", "CVE-2023-9999"}
        log4j = by_cve["CVE-2021-44228"]
        assert log4j.ransomware is True
        assert log4j.date_added == date(2021, 12, 10)
        assert log4j.due_date == date(2021, 12, 24)
        assert by_cve["CVE-2023-9999"].due_date is None
        assert by_cve["CVE-2023-9999"].ransomware is False

    @pytest.mark.parametrize(
        "payload", [b"not json", b"[]", b'{"vulnerabilities": [{"cveID": "x"}]}']
    )
    def test_rejects_other_files(self, payload):
        with pytest.raises(FeedError):
            parse_kev(payload)


def _kev(cve: str, *, ransomware: bool = False) -> KevEntry:
    return KevEntry(
        cve_id=cve,
        date_added=date(2024, 1, 1),
        due_date=date(2024, 1, 22),
        ransomware=ransomware,
        name=f"{cve} name",
        required_action="Patch.",
    )


@pytest.mark.django_db
class TestStore:
    def test_feeds_update_their_own_columns(self):
        vuln_intel.store_kev([_kev("CVE-1", ransomware=True), _kev("CVE-2")])
        vuln_intel.store_epss(
            [EpssScore("CVE-1", 0.5, 0.9), EpssScore("CVE-3", 0.1, 0.4)]
        )

        one = VulnerabilityIntel.objects.get(cve_id="CVE-1")
        assert (one.kev, one.kev_ransomware, one.epss_score) == (True, True, 0.5)
        assert VulnerabilityIntel.objects.get(cve_id="CVE-3").kev is False

        # A new EPSS day changes scores and keeps the KEV columns.
        vuln_intel.store_epss([EpssScore("CVE-1", 0.7, 0.95)])
        one.refresh_from_db()
        assert (one.kev, one.epss_score) == (True, 0.7)

    def test_kev_removal_clears_the_flag(self):
        vuln_intel.store_kev([_kev("CVE-1"), _kev("CVE-2")])
        vuln_intel.store_kev([_kev("CVE-2")])
        one = VulnerabilityIntel.objects.get(cve_id="CVE-1")
        assert (one.kev, one.kev_due_date, one.kev_name) == (False, None, "")
        assert VulnerabilityIntel.objects.get(cve_id="CVE-2").kev is True

    def test_exploit_by_cve(self):
        vuln_intel.store_kev([_kev("CVE-2021-1")])
        vuln_intel.store_epss([EpssScore("CVE-2021-1", 0.25, 0.8)])
        found = vuln_intel.exploit_by_cve(["CVE-2021-1", "CVE-0000-0", "GHSA-x", ""])
        assert set(found) == {"CVE-2021-1"}
        assert found["CVE-2021-1"]["known_exploited"] is True
        assert found["CVE-2021-1"]["epss_score"] == 0.25
        assert found["CVE-2021-1"]["kev_due_date"] == date(2024, 1, 22)


def _fake_download(payloads: dict[str, bytes | Exception]):
    def download(url: str) -> bytes:
        value = payloads["epss" if "epss" in url else "kev"]
        if isinstance(value, Exception):
            raise value
        return value

    return download


@pytest.mark.django_db
class TestRefresh:
    def test_one_feed_failing_keeps_the_other(self):
        payloads = {
            "epss": gzip.compress(EPSS_CSV.encode()),
            "kev": FeedError("Download failed: timeout"),
        }
        with patch.object(vuln_intel, "download", _fake_download(payloads)):
            result = refresh_vuln_intel_task()

        assert result[0] == {
            "feed": "epss",
            "refreshed": True,
            "version": "2026-11-10",
            "count": 2,
        }
        assert result[1]["refreshed"] is False
        epss = VulnerabilityIntelFeed.objects.get(name="epss")
        kev = VulnerabilityIntelFeed.objects.get(name="kev")
        assert epss.record_count == 2 and epss.refreshed_at and not epss.last_error
        assert kev.refreshed_at is None and "timeout" in kev.last_error

        status = {feed["id"]: feed for feed in vuln_intel.feed_status()}
        assert status["epss"]["records"] == 2
        assert status["kev"]["records"] is None
        assert status["kev"]["last_error"]

    def test_feed_urls_can_be_overridden(self, monkeypatch):
        monkeypatch.setenv(vuln_intel.KEV_URL_ENV, "https://mirror.internal/kev.json")
        seen = []

        def download(url):
            seen.append(url)
            return json.dumps(KEV_JSON).encode()

        with patch.object(vuln_intel, "download", download):
            assert vuln_intel.refresh_feed("kev")["refreshed"] is True
        assert seen == ["https://mirror.internal/kev.json"]


class TestQuery:
    def test_parses_exploit_filter_and_sort(self):
        query = parse_query(
            {
                "filter[area]": "application_security",
                "filter[known_exploited]": "true",
                "sort": "-epss",
            }
        )
        assert query.exploited is True
        assert (query.sort, query.descending) == ("epss", True)
        assert parse_query({"filter[area]": "cloud"}).exploited is False


@pytest.mark.django_db
class TestAreaFindingsExploit:
    def _seed(self, provider):
        scan = _app_security_scan(provider)
        _finding(
            scan, "trivy-repo-log4j", severity="critical", check_id="CVE-2021-44228"
        )
        _finding(scan, "trivy-repo-low", severity="critical", check_id="CVE-2024-0001")
        _finding(scan, "trivy-repo-none", severity="critical", check_id="CVE-2099-0001")
        _finding(scan, "trivy-repo-misconfig", severity="high", check_id="AVD-AWS-0001")
        vuln_intel.store_kev([_kev("CVE-2021-44228", ransomware=True)])
        vuln_intel.store_epss(
            [
                EpssScore("CVE-2021-44228", 0.94, 0.999),
                EpssScore("CVE-2024-0001", 0.0004, 0.11),
            ]
        )

    def test_rows_carry_exploit_fields(self, authenticated_client, aws_provider):
        self._seed(aws_provider)
        response = _list(authenticated_client, "application_security")
        assert response.status_code == 200, response.content
        rows = {
            item["attributes"]["uid"]: item["attributes"]
            for item in response.json()["data"]
        }
        log4j = rows["trivy-repo-log4j"]
        assert log4j["known_exploited"] is True
        assert log4j["kev_ransomware"] is True
        assert log4j["epss_score"] == 0.94
        assert log4j["kev_due_date"] == "2024-01-22"
        assert rows["trivy-repo-none"]["epss_score"] is None
        assert rows["trivy-repo-none"]["known_exploited"] is False
        assert rows["trivy-repo-misconfig"]["known_exploited"] is False

    def test_known_exploited_filter(self, authenticated_client, aws_provider):
        self._seed(aws_provider)
        response = _list(
            authenticated_client,
            "application_security",
            **{"filter[known_exploited]": "true"},
        )
        assert _uids(response) == ["trivy-repo-log4j"]

    def test_sort_by_exploit_likelihood(self, authenticated_client, aws_provider):
        self._seed(aws_provider)
        response = _list(authenticated_client, "application_security", sort="-epss")
        uids = _uids(response)
        assert uids[:2] == ["trivy-repo-log4j", "trivy-repo-low"]
        # Findings without a score come last.
        assert set(uids[2:]) == {"trivy-repo-none", "trivy-repo-misconfig"}

    def test_other_areas_ignore_exploit_sort(self, authenticated_client, aws_provider):
        _finding(_scan(aws_provider), "cloud-1", check_id="s3_bucket_public")
        _policy_run(aws_provider, [{"VolumeId": "vol-1"}])
        cloud = _list(authenticated_client, "cloud", sort="-epss")
        assert _uids(cloud) == ["cloud-1"]
        assert cloud.json()["data"][0]["attributes"]["epss_score"] is None
        governance = _list(authenticated_client, "governance", sort="-epss")
        assert governance.status_code == 200, governance.content
        exploited = _list(
            authenticated_client,
            "governance",
            **{"filter[known_exploited]": "true"},
        )
        assert _uids(exploited) == []
