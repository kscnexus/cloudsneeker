"""Report coverage (RC-002, RC-003, PI-022): finding status scope and the
exceptions, remediation, license and SBOM reports."""

from __future__ import annotations

import json
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest
from api.db_utils import rls_transaction
from api.models import Finding, MuteRule, Provider, Scan, StateChoices
from cloudsneeker_api.models import (
    JSON_API_TYPE_PREFIX,
    AppSecComponent,
    AppSecFinding,
    AppSecSbom,
    FindingTriage,
    TrivyTarget,
)
from cloudsneeker_api.reports.data import assemble_report
from cloudsneeker_api.reports.schema import ReportFilters
from django.urls import reverse
from django.utils import timezone

JSONAPI = "application/vnd.api+json"


def _assemble(tenant, report_type, **filters):
    with rls_transaction(str(tenant.id)):
        return assemble_report(str(tenant.id), report_type, ReportFilters(**filters))


def _table(data, key):
    return next(table for table in data.tables if table.key == key)


def _scan(provider):
    now = timezone.now()
    return Scan.objects.create(
        tenant_id=provider.tenant_id,
        provider=provider,
        name="coverage scan",
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.COMPLETED,
        started_at=now,
        completed_at=now,
    )


def _finding(scan, check_id, severity="high", *, status="FAIL", muted=False):
    return Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid=f"{check_id}-{uuid4()}",
        scan=scan,
        status=status,
        status_extended=f"{check_id} detail",
        severity=severity,
        impact=severity,
        raw_result={},
        check_id=check_id,
        check_metadata={"CheckTitle": f"Title {check_id}"},
        muted=muted,
        compliance={},
        first_seen_at=timezone.now(),
    )


def _accept(tenant_id, uid, *, provider=None, expires_in=90, approver=None, **extra):
    return FindingTriage.objects.create(
        tenant_id=tenant_id,
        finding_uid=uid,
        check_id=extra.pop("check_id", uid[:40]),
        provider=provider,
        status=FindingTriage.Status.RISK_ACCEPTED,
        risk_reason=extra.pop("reason", "Compensating control in place"),
        risk_expires_on=timezone.now().date() + timedelta(days=expires_in),
        risk_approved_by=approver,
        risk_approved_at=timezone.now(),
        **extra,
    )


def _target(provider, name="shop repo", mode="repo"):
    return TrivyTarget.objects.create(
        tenant_id=provider.tenant_id,
        provider=provider,
        name=name,
        mode=mode,
        config={},
    )


def _appsec(target, **fields):
    now = timezone.now()
    values = {
        "category": AppSecFinding.Category.VULNERABILITY,
        "title": "Finding",
        "severity": "high",
        "state": AppSecFinding.State.OPEN,
        "priority": AppSecFinding.Priority.MEDIUM,
        "first_seen_at": now - timedelta(days=5),
        "last_seen_at": now,
    }
    values.update(fields)
    fingerprint = uuid4().hex
    return AppSecFinding.objects.create(
        tenant_id=target.tenant_id,
        target=target,
        fingerprint=fingerprint,
        uid=f"trivy-{fingerprint}",
        **values,
    )


def _sbom(target, version=1, **fields):
    return AppSecSbom.objects.create(
        tenant_id=target.tenant_id, target=target, version=version, **fields
    )


def _component(sbom, name, *, licenses=None, **fields):
    return AppSecComponent.objects.create(
        tenant_id=sbom.tenant_id,
        sbom=sbom,
        target=sbom.target,
        name=name,
        version=fields.pop("version", "1.0.0"),
        ecosystem=fields.pop("ecosystem", "npm"),
        licenses=licenses or [],
        **fields,
    )


@pytest.fixture
def scoped_cloud(tenants_fixture, aws_provider):
    """One cloud scan: active, risk-accepted, muted and passed findings."""
    tenant = tenants_fixture[0]
    scan = _scan(aws_provider)
    active = _finding(scan, "iam_root_mfa", "critical")
    accepted = _finding(scan, "s3_public", "high")
    muted = _finding(scan, "ec2_imdsv2", "medium", muted=True)
    _finding(scan, "cloudtrail_on", "high", status="PASS")
    _accept(tenant.id, accepted.uid, provider=aws_provider)
    return tenant, {"active": active, "accepted": accepted, "muted": muted}


@pytest.mark.django_db
class TestStatusScope:
    def test_default_keeps_original_counts(self, scoped_cloud):
        tenant, _ = scoped_cloud
        data = _assemble(tenant, "cloud_posture")
        assert data.status_totals == {"pass": 1, "fail": 2, "muted": 1, "manual": 0}
        assert data.severity_totals["critical"] == 1
        assert data.severity_totals["high"] == 1
        assert "status_scope" not in data.kpis
        findings = _table(data, "findings")
        assert findings.total == 2
        assert "exception" not in dict(findings.columns)
        assert "status_scope" not in data.to_dict()["filters"]

    def test_active_leaves_out_accepted_risks(self, scoped_cloud):
        tenant, rows = scoped_cloud
        data = _assemble(tenant, "cloud_posture", status_scope="active")
        assert data.status_totals["fail"] == 1
        assert data.severity_totals["high"] == 0
        assert data.kpis["risk_accepted_findings"] == 1
        assert data.kpis["status_scope"].startswith("Active")
        assert data.grade != "N/A"
        findings = _table(data, "findings")
        assert [row["check_id"] for row in findings.rows] == ["iam_root_mfa"]
        assert findings.rows[0]["exception"] == "Active"
        assert [risk["check_id"] for risk in data.top_risks] == ["iam_root_mfa"]
        assert data.to_dict()["filters"]["status_scope"] == "active"

    def test_muted_lists_only_muted_findings(self, scoped_cloud):
        tenant, _ = scoped_cloud
        data = _assemble(tenant, "cloud_posture", status_scope="muted")
        assert data.status_totals["fail"] == 1
        assert data.severity_totals["medium"] == 1
        assert data.grade == "N/A" and data.score is None
        assert data.headline.startswith("1 muted cloud findings")
        findings = _table(data, "findings")
        assert [row["check_id"] for row in findings.rows] == ["ec2_imdsv2"]
        assert findings.rows[0]["exception"] == "Muted"
        assert data.top_risks[0]["check_id"] == "ec2_imdsv2"

    def test_accepted_lists_only_risk_accepted_findings(self, scoped_cloud):
        tenant, _ = scoped_cloud
        data = _assemble(tenant, "cloud_posture", status_scope="accepted")
        findings = _table(data, "findings")
        assert [row["check_id"] for row in findings.rows] == ["s3_public"]
        assert findings.rows[0]["exception"] == "Risk accepted"
        assert data.severity_totals["high"] == 1

    def test_all_lists_every_failed_finding(self, scoped_cloud):
        tenant, _ = scoped_cloud
        data = _assemble(tenant, "cloud_posture", status_scope="all")
        assert data.status_totals["fail"] == 3
        labels = {
            row["check_id"]: row["exception"] for row in _table(data, "findings").rows
        }
        assert labels == {
            "iam_root_mfa": "Active",
            "s3_public": "Risk accepted",
            "ec2_imdsv2": "Muted",
        }
        assert sum(point["fail"] for point in data.trend) == 3

    def test_other_tenant_acceptance_is_ignored(self, scoped_cloud, tenants_fixture):
        tenant, rows = scoped_cloud
        other = tenants_fixture[1]
        _accept(other.id, rows["active"].uid)
        data = _assemble(tenant, "cloud_posture", status_scope="accepted")
        assert [row["check_id"] for row in _table(data, "findings").rows] == [
            "s3_public"
        ]


@pytest.mark.django_db
class TestStatusScopeApi:
    def _post(self, client, attributes):
        body = json.dumps(
            {
                "data": {
                    "type": f"{JSON_API_TYPE_PREFIX}report-runs",
                    "attributes": attributes,
                }
            }
        )
        with patch("cloudsneeker_api.reports.runs.transaction.on_commit"):
            return client.post(
                reverse("report-runs-list"), data=body, content_type=JSONAPI
            )

    def test_accepts_scope_on_findings_reports(self, authenticated_client):
        response = self._post(
            authenticated_client,
            {"report_type": "sca", "params": {"status_scope": "muted"}},
        )
        assert response.status_code == 202, response.content
        assert (
            response.json()["data"]["attributes"]["params"]["status_scope"] == "muted"
        )

    @pytest.mark.parametrize(
        "attributes",
        [
            {"report_type": "sca", "params": {"status_scope": "hidden"}},
            {"report_type": "executive", "params": {"status_scope": "muted"}},
        ],
    )
    def test_rejects_invalid_scope(self, authenticated_client, attributes):
        assert self._post(authenticated_client, attributes).status_code == 400

    @pytest.mark.parametrize(
        "report_type", ["exceptions", "remediation", "licenses", "sbom"]
    )
    def test_new_types_are_listed_and_accepted(self, authenticated_client, report_type):
        listing = authenticated_client.get(reverse("report-types-list"))
        assert report_type in {item["id"] for item in listing.json()["data"]}
        assert (
            self._post(authenticated_client, {"report_type": report_type}).status_code
            == 202
        )


@pytest.mark.django_db
class TestExceptionsReport:
    def test_lists_rules_and_acceptances(
        self, tenants_fixture, aws_provider_pair, create_test_user
    ):
        tenant = tenants_fixture[0]
        first, second = aws_provider_pair
        user = create_test_user
        finding = _finding(_scan(first), "s3_public")
        MuteRule.objects.create(
            tenant_id=tenant.id,
            name="Lab accounts",
            reason="Sandbox only",
            finding_uids=[finding.uid, "unknown-uid"],
            created_by=user,
        )
        MuteRule.objects.create(
            tenant_id=tenant.id,
            name="Old rule",
            reason="Retired",
            finding_uids=["gone-uid"],
            enabled=False,
        )
        _accept(tenant.id, "uid-soon", provider=first, expires_in=10, approver=user)
        _accept(tenant.id, "uid-late", provider=first, expires_in=120)
        _accept(tenant.id, "uid-past", provider=first, expires_in=-1)
        _accept(tenant.id, "uid-other", provider=second, expires_in=200)
        FindingTriage.objects.create(
            tenant_id=tenant.id,
            finding_uid="uid-fp",
            provider=first,
            status=FindingTriage.Status.FALSE_POSITIVE,
        )
        FindingTriage.objects.create(
            tenant_id=tenant.id,
            finding_uid="uid-reopened",
            provider=first,
            status=FindingTriage.Status.REOPENED,
            risk_reason="Expired exception",
            risk_expires_on=timezone.now().date() - timedelta(days=3),
            risk_expired_at=timezone.now() - timedelta(days=2),
        )
        MuteRule.objects.create(
            tenant_id=tenants_fixture[1].id,
            name="Other tenant",
            reason="Not ours",
            finding_uids=["x"],
        )

        data = _assemble(tenant, "exceptions")

        assert not data.is_empty
        assert data.grade == "N/A"
        assert data.kpis["mute_rules"] == 2
        assert data.kpis["active_mute_rules"] == 1
        assert data.kpis["muted_by_rules"] == 2
        assert data.kpis["accepted_risks"] == 4
        assert data.kpis["expiring_in_30_days"] == 1
        assert data.kpis["expired"] == 2
        assert data.kpis["false_positives"] == 1
        accepted = _table(data, "accepted_risks").rows
        assert accepted[0]["finding_uid"] == "uid-past"
        assert accepted[0]["state"] == "Expired"
        soon = next(row for row in accepted if row["finding_uid"] == "uid-soon")
        assert soon["approved_by"] == user.email
        assert soon["state"].startswith("Expires in 10")
        rules = _table(data, "mute_rules").rows
        assert [row["name"] for row in rules] == ["Lab accounts", "Old rule"]
        assert rules[0]["created_by"] == user.email
        assert [
            row["finding_uid"] for row in _table(data, "expired_acceptances").rows
        ] == ["uid-reopened"]
        assert data.remediation

    def test_provider_scope_hides_other_rules_and_acceptances(
        self, tenants_fixture, aws_provider_pair
    ):
        tenant = tenants_fixture[0]
        first, second = aws_provider_pair
        finding = _finding(_scan(first), "s3_public")
        MuteRule.objects.create(
            tenant_id=tenant.id,
            name="First only",
            reason="Sandbox",
            finding_uids=[finding.uid],
        )
        _accept(tenant.id, "uid-first", provider=first)
        _accept(tenant.id, "uid-second", provider=second)

        only_second = _assemble(tenant, "exceptions", provider_ids=[str(second.id)])
        assert only_second.kpis["mute_rules"] == 0
        assert [
            row["finding_uid"] for row in _table(only_second, "accepted_risks").rows
        ] == ["uid-second"]
        only_first = _assemble(tenant, "exceptions", provider_ids=[str(first.id)])
        assert only_first.kpis["mute_rules"] == 1
        assert _table(only_first, "mute_rules").rows[0]["findings"] == 1


@pytest.mark.django_db
class TestRemediationReport:
    def test_lifecycle_figures(self, tenants_fixture, iac_provider):
        tenant = tenants_fixture[0]
        target = _target(iac_provider)
        now = timezone.now()
        _appsec(
            target,
            priority="urgent",
            due_at=now - timedelta(days=2),
            severity="critical",
        )
        _appsec(target, priority="high", due_at=now + timedelta(days=5))
        _appsec(target, priority="medium", state="reopened", reopen_count=1)
        _appsec(target, priority="low", suppressed=True, due_at=now - timedelta(days=9))
        closed = _appsec(target, priority="high", due_at=now - timedelta(days=1))
        _accept(tenant.id, closed.uid, provider=iac_provider)
        _appsec(
            target,
            state="fixed",
            first_seen_at=now - timedelta(days=10),
            fixed_at=now - timedelta(days=2),
        )
        _appsec(
            target,
            state="fixed",
            first_seen_at=now - timedelta(days=90),
            fixed_at=now - timedelta(days=60),
        )
        FindingTriage.objects.create(
            tenant_id=tenant.id,
            finding_uid="cloud-uid",
            area=FindingTriage.Area.CLOUD,
            status=FindingTriage.Status.REMEDIATING,
        )

        data = _assemble(tenant, "remediation")

        assert data.kpis["open_findings"] == 4
        assert data.kpis["open_urgent"] == 1
        assert data.kpis["overdue"] == 1
        assert data.kpis["fixed_in_period"] == 1
        assert data.kpis["mean_days_to_remediate"] == 8.0
        assert data.kpis["reopened_open"] == 1
        assert data.kpis["reopened_ever"] == 1
        assert data.severity_totals["critical"] == 1
        overdue = _table(data, "findings")
        assert overdue.total == 1 and overdue.rows[0]["priority"] == "urgent"
        assert overdue.rows[0]["days_overdue"] >= 1
        by_area = {row["area"]: row for row in _table(data, "triage_by_area").rows}
        assert by_area["Cloud Security"]["remediating"] == 1
        assert by_area["Application Security"]["risk_accepted"] == 0
        assert data.remediation[0]["action"].startswith("Fix the 1 overdue urgent")

    def test_provider_scope(self, tenants_fixture, provider_factory):
        tenant = tenants_fixture[0]
        first = provider_factory(Provider.ProviderChoices.IAC.value)
        second = provider_factory(Provider.ProviderChoices.IAC.value)
        _appsec(_target(first, "first repo"))
        _appsec(_target(second, "second repo"))
        _appsec(_target(second, "third repo"))
        data = _assemble(tenant, "remediation", provider_ids=[str(first.id)])
        assert data.kpis["open_findings"] == 1


@pytest.mark.django_db
class TestLicensesReport:
    def test_licenses_and_violations(self, tenants_fixture, iac_provider):
        tenant = tenants_fixture[0]
        target = _target(iac_provider)
        old = _sbom(target, version=1)
        _component(old, "legacy", licenses=["Apache-2.0"])
        latest = _sbom(target, version=2)
        _component(latest, "lodash", licenses=["MIT"])
        _component(latest, "react", licenses=["MIT"])
        _component(latest, "readline", licenses=["GPL-3.0"])
        _component(latest, "mystery")
        _appsec(
            target,
            category="license",
            rule_id="GPL-3.0",
            pkg_name="readline",
            severity="high",
            details={"license_category": "restricted"},
        )
        _appsec(
            target,
            category="license",
            rule_id="GPL-3.0",
            pkg_name="other",
            suppressed=True,
            details={"license_category": "restricted"},
        )

        data = _assemble(tenant, "licenses")

        assert data.kpis["licenses_in_use"] == 2
        assert data.kpis["components"] == 4
        assert data.kpis["components_without_license"] == 1
        assert data.kpis["policy_violations"] == 1
        rows = {row["license"]: row for row in _table(data, "licenses").rows}
        assert "Apache-2.0" not in rows
        assert rows["MIT"]["components"] == 2 and rows["MIT"]["targets"] == 1
        assert rows["GPL-3.0"]["violations"] == 1
        assert rows["GPL-3.0"]["category"] == "restricted"
        violations = _table(data, "violations").rows
        assert [row["package"] for row in violations] == ["readline"]
        assert data.severity_totals["high"] == 1


@pytest.mark.django_db
class TestSbomReport:
    def test_latest_inventory_per_target(self, tenants_fixture, provider_factory):
        tenant = tenants_fixture[0]
        first = provider_factory(Provider.ProviderChoices.IAC.value)
        second = provider_factory(Provider.ProviderChoices.IMAGE.value)
        repo = _target(first, "shop repo")
        image = _target(second, "shop image", mode="image")
        _sbom(repo, version=1, component_count=99)
        latest = _sbom(
            repo,
            version=2,
            component_count=3,
            vulnerable_component_count=2,
            vulnerability_count=5,
            summary={"ecosystems": {"npm": 2, "pip": 1}},
        )
        _component(
            latest,
            "lodash",
            vulnerability_count=3,
            max_severity="high",
            fixed_version="4.17.21",
        )
        _component(latest, "minimist", vulnerability_count=2, max_severity="critical")
        _component(latest, "react")
        image_sbom = _sbom(
            image, version=1, component_count=1, summary={"ecosystems": {"debian": 1}}
        )
        _component(
            image_sbom,
            "openssl",
            ecosystem="debian",
            vulnerability_count=1,
            max_severity="low",
        )

        data = _assemble(tenant, "sbom")

        assert data.kpis["targets_with_sbom"] == 2
        assert data.kpis["components"] == 4
        assert data.kpis["vulnerable_components"] == 2
        assert data.kpis["vulnerabilities"] == 5
        assert data.kpis["ecosystems"] == 3
        assert data.kpis["vulnerable_components_with_fix"] == 1
        inventories = {row["target"]: row for row in _table(data, "inventories").rows}
        assert inventories["shop repo"]["version"] == 2
        assert inventories["shop repo"]["ecosystems"] == "npm, pip"
        components = _table(data, "vulnerable_components").rows
        assert [row["name"] for row in components] == ["minimist", "lodash", "openssl"]
        assert data.severity_totals["critical"] == 1

        scoped = _assemble(tenant, "sbom", provider_ids=[str(second.id)])
        assert scoped.kpis["targets_with_sbom"] == 1
        assert [row["target"] for row in _table(scoped, "inventories").rows] == [
            "shop image"
        ]
        floor = _assemble(tenant, "sbom", severity_floor="high")
        assert [row["name"] for row in _table(floor, "vulnerable_components").rows] == [
            "minimist",
            "lodash",
        ]
