"""Security categories of Application Security findings."""

from __future__ import annotations

import pytest
from api.models import Finding, Scan, StateChoices
from cloudsneeker_api.models import TrivyRun, TrivyTarget
from cloudsneeker_api.services.app_security_categories import (
    SECURITY_CATEGORIES,
    SECURITY_CATEGORY,
    classify,
    target_categories,
)
from cloudsneeker_api.services.area_findings import AreaFindingsError, parse_query
from django.urls import reverse
from django.utils import timezone

VULN = {"VulnerabilityID": "CVE-2024-1", "PkgName": "lodash", "InstalledVersion": "1"}
SECRET = {"RuleID": "aws-access-key-id", "Category": "AWS", "Match": "AKIA****"}
LICENSE = {"Category": "restricted", "Name": "GPL-3.0", "PkgName": "lib"}
SAST = {"check_id": "python.sqli", "path": "app.py", "extra": {"message": "x"}}
MISCONFIG = {"ID": "AVD-AWS-0086", "Resolution": "Block public access"}


class TestClassify:
    @pytest.mark.parametrize(
        ("raw", "mode", "expected"),
        [
            (SECRET, "repo", SECURITY_CATEGORY.SECRETS),
            (SECRET, "image", SECURITY_CATEGORY.SECRETS),
            (SAST, "sast", SECURITY_CATEGORY.SAST),
            (VULN, "repo", SECURITY_CATEGORY.SCA),
            (VULN, "sbom", SECURITY_CATEGORY.SCA),
            (VULN, "image", SECURITY_CATEGORY.CONTAINER),
            (VULN, "k8s", SECURITY_CATEGORY.CONTAINER),
            (LICENSE, "repo", SECURITY_CATEGORY.SCA),
            (MISCONFIG, "repo", SECURITY_CATEGORY.IAC),
            (MISCONFIG, "k8s", SECURITY_CATEGORY.IAC),
            (MISCONFIG, "image", SECURITY_CATEGORY.CONTAINER),
            ({}, None, SECURITY_CATEGORY.IAC),
            (None, "repo", SECURITY_CATEGORY.IAC),
        ],
    )
    def test_one_category_per_finding(self, raw, mode, expected):
        assert classify(raw, mode) == expected

    def test_severity_never_changes_the_category(self):
        assert classify({**VULN, "Severity": "CRITICAL"}, "repo") == "sca"

    def test_target_categories_follow_mode_and_scanners(self):
        assert target_categories("sast", []) == {"sast"}
        assert target_categories("repo", ["vuln", "secret", "misconfig"]) == {
            "sca",
            "secrets",
            "iac",
        }
        assert target_categories("image", ["vuln", "misconfig"]) == {"container"}
        assert target_categories("sbom", ["vuln", "license"]) == {"sca"}


class TestParseCategories:
    def test_reads_categories(self):
        query = parse_query(
            {
                "filter[area]": "application_security",
                "filter[category__in]": "SAST,secrets",
            }
        )
        assert query.categories == ["sast", "secrets"]

    @pytest.mark.parametrize(
        "params",
        [
            {"filter[area]": "application_security", "filter[category__in]": "dast"},
            {"filter[area]": "cloud", "filter[category__in]": "sast"},
        ],
    )
    def test_rejects_unknown_or_misplaced(self, params):
        with pytest.raises(AreaFindingsError):
            parse_query(params)


def _target_scan(provider, name: str, mode: str, scanners=None) -> Scan:
    now = timezone.now()
    scan = Scan.objects.create(
        tenant_id=provider.tenant_id,
        provider=provider,
        name=name,
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.COMPLETED,
        started_at=now,
        completed_at=now,
        scanner_args={"source": "trivy_hub", "mode": mode},
    )
    target = TrivyTarget.objects.create(
        tenant_id=provider.tenant_id,
        name=name,
        mode=mode,
        provider=provider,
        config={"scanners": scanners} if scanners else {},
    )
    TrivyRun.objects.create(
        tenant_id=provider.tenant_id,
        target=target,
        provider=provider,
        status=TrivyRun.Status.COMPLETED,
        finished_at=now,
        scan_id=scan.id,
    )
    return scan


def _finding(scan: Scan, uid: str, raw: dict, severity: str = "high") -> Finding:
    return Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid=uid,
        scan=scan,
        status="FAIL",
        status_extended="detail",
        severity=severity,
        impact=severity,
        raw_result=raw,
        check_id=uid,
        check_metadata={"CheckTitle": uid, "Description": "desc"},
        first_seen_at=timezone.now(),
    )


def _list(client, **params):
    return client.get(
        reverse("area-findings-list"),
        {"filter[area]": "application_security", **params},
    )


@pytest.mark.django_db
class TestCategoryApi:
    @pytest.fixture
    def findings(self, aws_provider):
        repo = _target_scan(aws_provider, "web-repo", "repo")
        image = _target_scan(aws_provider, "web-image", "image", ["vuln"])
        _finding(repo, "repo-vuln", VULN, "critical")
        _finding(repo, "repo-secret", SECRET)
        _finding(repo, "repo-misconfig", MISCONFIG, "low")
        _finding(image, "image-vuln", VULN, "critical")

    def test_rows_carry_their_category(self, authenticated_client, findings):
        response = _list(authenticated_client)
        assert response.status_code == 200, response.content
        categories = {
            row["attributes"]["uid"]: row["attributes"]["security_category"]
            for row in response.json()["data"]
        }
        assert categories == {
            "repo-vuln": "sca",
            "repo-secret": "secrets",
            "repo-misconfig": "iac",
            "image-vuln": "container",
        }

    def test_counts_add_up_to_the_total(self, authenticated_client, findings):
        meta = _list(authenticated_client).json()["meta"]
        counts = meta["category_counts"]
        assert set(counts) == set(SECURITY_CATEGORIES)
        assert sum(counts.values()) == meta["pagination"]["count"] == 4
        assert counts["sast"] == 0
        assert meta["enabled_categories"] == ["sca", "secrets", "iac", "container"]

    def test_category_filter_keeps_counts_of_other_filters(
        self, authenticated_client, findings
    ):
        response = _list(
            authenticated_client,
            **{"filter[category__in]": "container", "filter[severity__in]": "critical"},
        )
        body = response.json()
        assert [row["attributes"]["uid"] for row in body["data"]] == ["image-vuln"]
        # Counts ignore the category filter but honour severity.
        assert body["meta"]["category_counts"]["sca"] == 1
        assert body["meta"]["category_counts"]["container"] == 1
        assert body["meta"]["category_counts"]["iac"] == 0

    def test_bad_category_is_400(self, authenticated_client):
        assert (
            _list(authenticated_client, **{"filter[category__in]": "x"}).status_code
            == 400
        )

    def test_other_areas_have_no_category_meta(self, authenticated_client):
        response = authenticated_client.get(
            reverse("area-findings-list"), {"filter[area]": "cloud"}
        )
        assert response.status_code == 200, response.content
        assert "category_counts" not in response.json()["meta"]
