"""Risk priority, remediation due dates and the extra findings filters."""

from __future__ import annotations

from datetime import timedelta

import pytest
from cloudsneeker_api.models import FindingTriage, VulnerabilityIntel
from cloudsneeker_api.services.app_security_priority import (
    PRIORITY,
    due_at,
    is_overdue,
    priority,
)
from cloudsneeker_api.services.area_findings import AreaFindingsError, parse_query
from cloudsneeker_api.tests.test_app_security_categories import (
    SECRET,
    VULN,
    _finding,
    _list,
    _target_scan,
)
from django.utils import timezone


class TestPriority:
    @pytest.mark.parametrize(
        ("severity", "category", "kev", "epss", "expected"),
        [
            ("high", "sca", True, None, PRIORITY.P0),
            ("critical", "secrets", False, None, PRIORITY.P0),
            ("critical", "sca", False, None, PRIORITY.P1),
            ("low", "sca", True, None, PRIORITY.P1),
            ("high", "sca", False, 0.4, PRIORITY.P1),
            ("high", "secrets", False, None, PRIORITY.P1),
            ("high", "sca", False, 0.01, PRIORITY.P2),
            ("medium", "iac", False, None, PRIORITY.P3),
            ("low", "iac", False, None, PRIORITY.P4),
            ("informational", "sast", False, None, PRIORITY.P4),
        ],
    )
    def test_rules(self, severity, category, kev, epss, expected):
        assert (
            priority(severity, category, known_exploited=kev, epss_score=epss)
            == expected
        )

    def test_due_and_overdue(self):
        now = timezone.now()
        seen = now - timedelta(days=10)
        assert due_at(seen, PRIORITY.P1) == seen + timedelta(days=7)
        assert is_overdue(seen, PRIORITY.P1, "open", now)
        assert not is_overdue(seen, PRIORITY.P2, "open", now)
        assert not is_overdue(seen, PRIORITY.P1, "resolved", now)
        assert not is_overdue(None, PRIORITY.P1, "open", now)


class TestParse:
    def test_reads_filters(self):
        query = parse_query(
            {
                "filter[area]": "application_security",
                "filter[priority__in]": "P0,p1",
                "filter[overdue]": "true",
                "filter[application__in]": "a,b",
                "filter[uid]": " u1 ",
            }
        )
        assert query.priorities == ["p0", "p1"]
        assert query.overdue
        assert query.applications == ["a", "b"]
        assert query.uid == "u1"

    @pytest.mark.parametrize(
        "params",
        [
            {"filter[area]": "application_security", "filter[priority__in]": "p9"},
            {"filter[area]": "cloud", "filter[overdue]": "true"},
            {"filter[area]": "governance", "filter[uid]": "x"},
        ],
    )
    def test_rejects(self, params):
        with pytest.raises(AreaFindingsError):
            parse_query(params)


@pytest.mark.django_db
class TestPriorityApi:
    @pytest.fixture
    def findings(self, aws_provider, provider_factory):
        VulnerabilityIntel.objects.create(cve_id="CVE-2024-9", kev=True)
        repo = _target_scan(aws_provider, "web-repo", "repo")
        old = _finding(
            repo, "CVE-2024-9", {**VULN, "VulnerabilityID": "CVE-2024-9"}, "high"
        )
        old.first_seen_at = timezone.now() - timedelta(days=5)
        old.save(update_fields=["first_seen_at"])
        _finding(repo, "repo-secret", SECRET, "high")
        _finding(repo, "repo-medium", VULN, "medium")
        other = _target_scan(provider_factory("iac"), "api-repo", "repo")
        _finding(other, "api-low", VULN, "low")
        return aws_provider

    def _rows(self, response):
        assert response.status_code == 200, response.content
        return {
            row["attributes"]["uid"]: row["attributes"]
            for row in response.json()["data"]
        }

    def test_rows_carry_priority_and_due_date(self, authenticated_client, findings):
        rows = self._rows(_list(authenticated_client))
        assert rows["CVE-2024-9"]["priority"] == "p0"
        assert rows["CVE-2024-9"]["overdue"] is True
        assert rows["CVE-2024-9"]["due_at"]
        assert rows["repo-secret"]["priority"] == "p1"
        assert rows["repo-medium"]["priority"] == "p3"
        assert rows["repo-medium"]["overdue"] is False

    def test_priority_counts_and_filter(self, authenticated_client, findings):
        response = _list(authenticated_client, **{"filter[priority__in]": "p0,p1"})
        assert set(self._rows(response)) == {"CVE-2024-9", "repo-secret"}
        meta = response.json()["meta"]
        assert meta["priority_counts"] == {
            "p0": 1,
            "p1": 1,
            "p2": 0,
            "p3": 1,
            "p4": 1,
        }
        assert meta["overdue_count"] == 1

    def test_overdue_skips_closed_triage(self, authenticated_client, findings):
        assert set(
            self._rows(_list(authenticated_client, **{"filter[overdue]": "true"}))
        ) == {"CVE-2024-9"}
        FindingTriage.objects.create(
            tenant_id=findings.tenant_id,
            finding_uid="CVE-2024-9",
            area="application_security",
            status=FindingTriage.Status.RESOLVED,
            provider=findings,
        )
        assert (
            self._rows(_list(authenticated_client, **{"filter[overdue]": "true"})) == {}
        )

    def test_uid_and_application_filters(self, authenticated_client, findings):
        assert set(
            self._rows(_list(authenticated_client, **{"filter[uid]": "repo-secret"}))
        ) == {"repo-secret"}
        rows = self._rows(
            _list(authenticated_client, **{"filter[application__in]": str(findings.id)})
        )
        assert "api-low" not in rows
        assert len(rows) == 3

    def test_application_summary(self, authenticated_client, findings):
        meta = _list(authenticated_client, summary="applications").json()["meta"]
        by_id = {item["id"]: item for item in meta["applications"]}
        assert by_id[str(findings.id)] == {
            "id": str(findings.id),
            "total": 3,
            "critical": 0,
            "high": 2,
            "urgent": 2,
        }
        assert len(by_id) == 2
